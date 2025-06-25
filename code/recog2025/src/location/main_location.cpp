#include <iostream>
#include <cstring>
#include <time.h>
#include <bits/stdc++.h>

#include "_lib.h/libconfig.h++"
#include "_lib.h/libPcapSE.h"
#include "winlin/winlinux.h"

#include "location/location.h"

using namespace std;  
using namespace libconfig;

int main(int argc, char *argv[])
{
    char buf[UINT8_MAX] = "data.cfg";

    if(argc==2)
        strcpy(buf, argv[1]);

    std::cerr << "begin" << std::endl;        

    Config cfg;
    try
    {
        cfg.readFile(buf);
    }
    catch(...)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return(EXIT_FAILURE);
    }    

    try
    {
        //path
        string path = cfg.lookup("LOC_Path");    
        cout << "path name: " << path << endl;
        string filter = cfg.lookup("LOC_SNI_filter");    
        cout << "SNI filter: " << filter << endl;
        int num_adu;
        cfg.lookupValue("LOC_NUM_ADU", num_adu);
        cout << "number of ADU:" << num_adu << endl;

        if(path.length()>0)
        {
            vector<string> vctFN;
            if(iterPathPcaps(path, &vctFN))
            {
                path_data *lp_PD = new path_data();

                for(vector<string>::iterator iter=vctFN.begin(); iter!=vctFN.end(); ++iter)
                {
                    string strFN = *iter;
                    cout << "pcap file:" << strFN << endl;

                    packet_statistics_object_type typeS = pso_IPPortPair;
                    IFlow2Stat* lpFS = CFlow2StatCreator::create_flow2_stat(strFN, 25, 1, 0);
                    I_TLS_flow_stat* lp_TLS = TLS_flow_stat_creator::create_TLS_flow_stat();
                    if(lp_TLS && lp_TLS->check_stat_buffer())
                    {
                        loc_flow_creator* lpFC = new loc_flow_creator(typeS, strFN, filter, lp_TLS);
                        if(lpFS && lpFC)
                        {
                            lpFS->setParameter(typeS, 1, psm_SouDstDouble, true);
                            lpFS->setCreator(lpFC);
                            lp_PD->add_id(strFN);
                            lpFC->set_path_data(lp_PD);
                            if(lpFS->isChecked())
                                lpFS->iterPcap();
                            delete lpFC;
                            delete lpFS;
                        }
                        else
                            cout << "pcap file " << strFN << " open error!" << endl;

                        delete lp_TLS;
                    }
                }

                string file_path =  path + "0_stat_by_SNI.csv";
                lp_PD->save_SNI_adu(file_path, path, num_adu);
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return(EXIT_FAILURE);
    }

    return 0;
}