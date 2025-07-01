#include <iostream>

#include "location/location.h"

using namespace std;


void path_data::add_adu(stt_HTTP_ADU st_adu, std::string str_sni)
{
    if(!str_sni.empty() && str_sni != "N/A")
    {
        bool bfind = false;
        for(vector<sni_adu*>::iterator iter=vct_sni.begin(); iter!=vct_sni.end(); ++iter)
        {
            if(*iter)
            {
                if((*iter)->get_SNI() == str_sni)
                {
                    (*iter)->add_adu(pcap_id, st_adu, loc_id);
                    bfind = true;
                }
            }
        }
        if(!bfind)
        {
            sni_adu* lp_sni = new sni_adu(str_sni);
            if(lp_sni)
            {
                lp_sni->add_adu(pcap_id, st_adu, loc_id);
                vct_sni.push_back(lp_sni);
            }
        }
    }
}

bool path_data::save_SNI_adu(std::string fname, std::string fpath, int num)
{
    bool bout = false;
    FILE* fp = fopen(fname.c_str(), "wt");
    if(fp)
    {
        int half_id = pcap_id/2;
        bout = true;
        for(vector<sni_adu*>::iterator iter=vct_sni.begin(); iter!=vct_sni.end(); ++iter)
        {
            if(*iter)
                (*iter)->save_adu(fp, half_id, fpath, num);
        }
        fclose(fp);
    }
    else
        cout << "Error opening file " << fname << endl;
    
    return bout;
    
}

int path_data::get_location_id(std::string fname)
{
    int iout = 0;
    char buf[256];

    strcpy(buf, fname.c_str());
    char* pos = strstr(buf, "loc");
    if(pos)
    {
        char* pose = strstr(pos, ".");
        if(pose)
        {
            *pose = 0;
            iout = atoi(pos+3);
        }
    }
    return iout;
}

void sni_adu::save_adu(FILE* fp, int half, string fpath, int num_adu)
{
    if(fp)
    {
        int cur = 0, num = 0;
        for(vector<stt_pcap_adu>::iterator iter=vct_pcap_adu.begin(); iter!=vct_pcap_adu.end(); ++iter)
        {
            if((*iter).pcap_id != cur)
            {
                num ++;
                cur = (*iter).pcap_id;
            }
        }
        if(num > half)
        {
            fprintf(fp, "SNI,%s\n", str_SNI.c_str());
            fprintf(fp, "f_id,c_num_tls,c_len,s_num_tls,s_len,s_esti1,s_esti2\n");
            for(vector<stt_pcap_adu>::iterator iter=vct_pcap_adu.begin(); iter!=vct_pcap_adu.end(); ++iter)
            {
                fprintf(fp, "%d,%d,%d,%d,%d,%d,%d,", (*iter).pcap_id,
                            (*iter).st_adu.num_TLS_requ, (*iter).st_adu.len_TLS_requ, 
                            (*iter).st_adu.num_TLS_resp, (*iter).st_adu.len_TLS_resp, 
                            (*iter).st_adu.len_estimate1, (*iter).st_adu.len_estimate2);
                fprintf(fp, ",,");
                for(vector<uint32_t>::iterator iter_len=(*iter).st_adu.vct_TLS_datalen.begin(); 
                                            iter_len!=(*iter).st_adu.vct_TLS_datalen.end(); 
                                            ++iter_len)
                    fprintf(fp, "%d,", (*iter_len));
                fprintf(fp, "\n");
            }

            string fname = fpath + "1_" + str_SNI + ".num_" + to_string(num_adu) + ".ADU.csv";
            FILE* fp_sni = fopen(fname.c_str(), "wt");
            if(fp_sni)
            {
                fprintf(fp_sni, "loc,");
                for(int i = 0; i< num_adu; i++)
                    fprintf(fp_sni, "cn%d,cl%d,sn%d,sl%d,", i+1, i+1, i+1, i+1);
                fprintf(fp_sni, "\n");

                for(vector<stt_pcap_adu>::iterator iter=vct_pcap_adu.begin(); iter!=vct_pcap_adu.end(); ++iter)
                {
                    fprintf(fp_sni, "%d,%d,%d,%d,%d,", (*iter).loc_id, 
                                                       (*iter).st_adu.num_TLS_requ, (*iter).st_adu.len_TLS_requ,
                                                       (*iter).st_adu.num_TLS_resp, (*iter).st_adu.len_estimate1);
                    int j = 1;
                    for(vector<stt_pcap_adu>::iterator iter2=iter+1; iter2!=vct_pcap_adu.end(); ++iter2)
                    {
                        if((*iter).pcap_id == (*iter2).pcap_id)
                        {
                            iter = iter2;
                            if(j < num_adu)
                                fprintf(fp_sni, "%d,%d,%d,%d,", 
                                                       (*iter).st_adu.num_TLS_requ, (*iter).st_adu.len_TLS_requ,
                                                       (*iter).st_adu.num_TLS_resp, (*iter).st_adu.len_estimate1);
                            j++;
                        }
                        else
                            break;
                    }
                    for(; j< num_adu; j++)
                        fprintf(fp_sni, "0,0,0,0,");
                    fprintf(fp_sni, "\n");
                }
                fclose(fp_sni);
            }
            else
                cout << fname << " open file error!" << endl;
        }
    }
}
