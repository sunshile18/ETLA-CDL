#ifndef TLS_FLOW_H
#define TLS_FLOW_H

#include "_lib.h/lib_TLS2_SE.h"
#include <vector>
#include "_base_tools/std_flow2_TLS.h"

struct stt_pcap_adu
{
    int pcap_id;
    int loc_id;
    stt_HTTP_ADU st_adu;
};

class sni_adu
{
public:
    sni_adu(std::string str_sni) {str_SNI = str_sni;}
    ~sni_adu() {vct_pcap_adu.clear();}
public:
    std::string get_SNI() {return str_SNI;}
    void add_adu(int p_id, stt_HTTP_ADU st_ADU, int loc_id) {
        stt_pcap_adu st_padu;
        st_padu.pcap_id = p_id;
        st_padu.st_adu = st_ADU;
        st_padu.loc_id = loc_id;
        vct_pcap_adu.push_back(st_padu);
    }
    void save_adu(FILE* fp, int half, std::string fpath, int num);
private:
    std::string str_SNI;
    std::vector<stt_pcap_adu> vct_pcap_adu;
};

class path_data
{
public:
    path_data(){pcap_id = 0;}
    ~path_data(){
        for(std::vector<sni_adu*>::iterator iter=vct_sni.begin(); iter!=vct_sni.end(); ++iter)
            delete(*iter);
    }
public:
    void add_id(std::string fname){
        pcap_id++;
        loc_id = get_location_id(fname);
    }
public:
    void add_adu(stt_HTTP_ADU st_adu, std::string str_sni);
    bool save_SNI_adu(std::string fname, std::string fpath, int num);
private:
    int get_location_id(std::string fname);
private:
    int pcap_id, loc_id;
    std::vector<sni_adu*> vct_sni;
};

//==============================================================================
//==============================================================================
//==============================================================================

class loc_flow_creator: public IFlow2ObjectCreator
{
public:
    loc_flow_creator(packet_statistics_object_type type, std::string fname, 
                     std::string filter, I_TLS_flow_stat* lp_stat);
    ~loc_flow_creator();
public:    
    packet_statistics_object_type getStatType() {return pso_type;}
    bool isSave() {return true;}
    std::string getName() {return str_tls;}
    I_TLS_flow_stat* get_TLS_stat() {return lp_TLS_stat;} 
public:
    std::string get_ADU() {return str_adu;}
    std::string get_filter() {return str_filter;}
    std::string get_pcap() {return str_pcap;}
    void set_path_data(path_data *lp_pd) {lp_path_data = lp_pd;}
public:
    IFlow2Object* create_Object(uint8_t* buf, int len);
    void add_ADU(stt_HTTP_ADU st_adu, std::string str_sni){
        if(lp_path_data)
            lp_path_data->add_adu(st_adu, str_sni);
    }
private:
    bool open_csv(std::string str_name){
        bool bout = false;
        FILE* fp = fopen(str_name.c_str(), "wt");
        if(fp)
        {
            fclose(fp);
            bout = true;
        }
        else
            std::cout << "open file error, file:" << str_name << std::endl;
        return bout;
    }
private:
    packet_statistics_object_type pso_type;
    I_TLS_flow_stat* lp_TLS_stat;
    std::string str_pcap, str_tls, str_adu;
    std::string str_filter;
private:
    path_data *lp_path_data;
};

//==============================================================================
//==============================================================================
//==============================================================================

class loc_flow: public flow2_TLS
{
public:
    loc_flow(uint8_t* buf, int len, loc_flow_creator* lpFOC);
    ~loc_flow();
public:
    bool addPacket(CPacket* lppck, bool bSou);
    bool saveObject(FILE* fp, uint64_t cntP, bool bFin);
protected:  //TLS1
    void create_TLS_stat(CPacket* lppck, bool b_srv){
        I_TLS_flow_stat *lp_stat = lpCreator->get_TLS_stat();
        if(lp_stat){
            lp_TLS_flow = lp_stat->create_TLS_flow(1, 0);
            if(lp_TLS_flow)
            {
                lp_TLS_flow->set_base_seq(lppck, b_srv);
                lp_TLS_flow->set_client_requ_thre(100);
            }
        }
    }
private:
    loc_flow_creator* lpCreator;
    I_TLS_flow *lp_TLS_flow;
private:
    void save_ADU(std::vector<stt_HTTP_ADU> *lp_adu, char* lp_info);
private:
    std::vector<uint32_t> vct_segments;
};

#endif