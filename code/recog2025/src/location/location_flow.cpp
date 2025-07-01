#include <iostream>

#include "_lib.h/libHashSE.h"

#include "location/location.h"

using namespace std;

const int MIN_REQUEST = 60;
const int CH_threshold = 10;

loc_flow_creator::loc_flow_creator(packet_statistics_object_type type, std::string fname,
                                   std::string filter, I_TLS_flow_stat* lp_stat)
{
    pso_type = type;
    str_filter = filter;
    lp_TLS_stat = lp_stat;

    str_pcap = fname;
    str_tls = fname + ".TLS.csv";
    open_csv(str_tls);
    str_adu = fname + ".ADU.csv";
    open_csv(str_adu);

    lp_path_data = NULL;
}

loc_flow_creator::~loc_flow_creator()
{

}

IFlow2Object* loc_flow_creator::create_Object(uint8_t* buf, int len){
    loc_flow* lpFlow = new loc_flow(buf, len, this);
    return lpFlow;
}

//==============================================================================
//==============================================================================
//==============================================================================

loc_flow::loc_flow(uint8_t* buf, int len, loc_flow_creator* lpFC)
    :flow2_TLS(buf, len)
{
    lpCreator = lpFC;
    lp_TLS_flow = NULL;
}

loc_flow::~loc_flow()
{
    if(lp_TLS_flow)
        delete lp_TLS_flow;
}

bool loc_flow::addPacket(CPacket* lppck, bool bSou)
{
    bool bout = false;

    if(lppck)
    {
        bout = true;
        //通过CH的SNI对TLS flow进行处理
        if(i_TLS_state < 2 && bSou)
            check_TLS_CH(lppck, lpCreator->get_filter());
        //选中的TLS flow进行数据处理
        if(i_TLS_state == 2 || i_TLS_state == 1)
        {
            if(lp_TLS_flow)
            {
                bool b_adu;
                int ret = lp_TLS_flow->TLS_flow_packet(lppck, !bSou, b_adu);
                if(ret<0)
                    i_TLS_state = 4;
            }
        }
    }
    return bout;
}

bool loc_flow::saveObject(FILE* fp, uint64_t cntP, bool bFin)
{
    bool bout = false;
    char buf_IPP[UINT8_MAX];
    char buf_info[1024];

    if(fp)
    {
        if(getPckCnt() > 2 && lp_TLS_flow && 
                (i_TLS_state==2 || i_TLS_state==4))
        {
            CPacketTools::getStr_IPportpair_from_hashbuf(bufKey, lenKey, buf_IPP);
            sprintf(buf_info, "Info.,%s,SNI,%s,,,Pck.,%u,TLS_ver,1.%d,", 
                    buf_IPP, str_SNI.c_str(), getPckCnt(), lp_TLS_flow->get_TLS_version()); 
            if(lp_TLS_flow->is_http2())
                strcat(buf_info, "H2\n");
            else
                strcat(buf_info, "\n");
            fprintf(fp, "%s", buf_info);

            vector<stt_TLS_record> *lp_records = lp_TLS_flow->get_TLS_vector();
            string strPck = "packet", strTime = "time", strFrag_c = "Fragment_c", strFrag_s = "Fragment_s";
            for(vector<stt_TLS_record>::iterator iter=lp_records->begin(); iter!=lp_records->end(); ++iter)
            {

                if((*iter).content_type==23)
                {
                    strPck += "," + to_string((*iter).pck_no);
                    char buf_time[50];
                    sprintf(buf_time, "%d.%06d", (*iter).tm_pck.tv_sec, (*iter).tm_pck.tv_usec);
                    strTime += "," + string(buf_time);
                    if(!(*iter).b_sc)
                    {
                        strFrag_c += "," + to_string((*iter).len_TLS);
                        strFrag_s += ",";
                    }
                    else
                    {
                        strFrag_s += "," + to_string((*iter).len_TLS);
                        strFrag_c += ",";
                    }
                }
            }
            fprintf(fp, "%s\n", strPck.c_str());
            fprintf(fp, "%s\n", strTime.c_str());
            fprintf(fp, "%s\n", strFrag_s.c_str());
            fprintf(fp, "%s\n", strFrag_c.c_str());
            fprintf(fp, "\n");

            vector<stt_HTTP_ADU> *lp_adu = lp_TLS_flow->get_ADU_vector();
            save_ADU(lp_adu, buf_info);
        }
        bout = true;

    }

    return bout;
}

void loc_flow::save_ADU(vector<stt_HTTP_ADU> *lp_adu, char* lp_info)
{
    if(lp_adu->size() > 0)
    {
        string fname = lpCreator->get_ADU();
        FILE *fp = fopen(fname.c_str(), "at");
        if(fp)
        {
            if(lp_info)
                fprintf(fp, "%s", lp_info);
            fprintf(fp, "pkn_c,time_c,ntls_c,len_c,,pkn_s,time_s_b,time_s_e,ntls_s,len_s,len_estimate,,,,source data len\n");
            for(vector<stt_HTTP_ADU>::iterator iter=lp_adu->begin(); iter!=lp_adu->end(); ++iter)
            {
                fprintf(fp, "%d,%d.%06d,%d,%d,,%d,%d.%06d,%d.%06d,%d,%d,%d,,,,", (*iter).pkn_requ, 
                        (*iter).tm_requ.tv_sec, (*iter).tm_requ.tv_usec, 
                        (*iter).num_TLS_requ, (*iter).len_TLS_requ, (*iter).pkn_resp, 
                        (*iter).tm_resp_b.tv_sec, (*iter).tm_resp_b.tv_usec, 
                        (*iter).tm_resp_e.tv_sec, (*iter).tm_resp_e.tv_usec, 
                        (*iter).num_TLS_resp, (*iter).len_TLS_resp, (*iter).len_estimate1);
                for(vector<uint32_t>::iterator iter_len=(*iter).vct_TLS_datalen.begin(); iter_len!=(*iter).vct_TLS_datalen.end(); ++iter_len)
                {
                    fprintf(fp, "%u,", (*iter_len));
                }
                fprintf(fp, "\n");
                lpCreator->add_ADU((*iter), str_SNI);
            }
            fclose(fp);
        }
    }
}
