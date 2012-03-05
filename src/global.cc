#include "./include/global.h"
#include "./include/rule_key.h"

int packet_id = 0;
const int kTCPPacketThreshold = 5;
const int kHTTPPacketThreshold = 2;

char http_regex[] = "(POST|GET) .* HTTP/(0\.9|1\.0|1\.1)";
char rtsp_regex[] = "GET[\x09-\x0d -~]* Accept: application/x-rtsp-tunnelled";
char ftp_regex[] = "^220[\x09-\x0d -~\x80-\xfd]*ftp";
const char *error;
int erroffset;
int ovector[30];
pcre* http_re = pcre_compile(http_regex, PCRE_CASELESS, &error, &erroffset, NULL);
pcre* rtsp_re = pcre_compile(rtsp_regex, PCRE_CASELESS, &error, &erroffset, NULL);
pcre* ftp_re = pcre_compile(ftp_regex, PCRE_CASELESS, &error, &erroffset, NULL);

map<string, string> domain_app;
vector<DomainKey> domain_table;
vector<Rule> all_rule_set;
vector<Rule>::iterator rule_iter = all_rule_set.begin();
vector<Rule>::iterator rule_iter_end = all_rule_set.end();

struct timeval GetStartTime()
{
	struct timeval tpstart;
	gettimeofday(&tpstart,NULL);
	return tpstart;
}

float GetEndTime(struct timeval tpstart)
{
	float timeuse = 0.0;
	struct timeval tpnow;
	gettimeofday(&tpnow,NULL);//record the end time
	timeuse = 1000000*(tpnow.tv_sec-tpstart.tv_sec) + tpnow.tv_usec - tpstart.tv_usec;
	timeuse /= 1000000;
	return timeuse;
}