/*----------------------*/
/*  Create by Toney Lee */
/*  MOE Lab XJTU        */
/*  2011.11.26          */
/*----------------------*/
#ifndef HOLMESII_GLOBAL_H_
#define HOLMESII_GLOBAL_H_

#include <string>
#include <vector>
#include <pcre.h>
#include <map>
#include "rule.h"
#include "rule_set.h"
#include <sys/time.h>

using std::map;
using std::string;
using std::vector;

struct RuleKey;

extern int packet_id;
extern const int kTCPPacketThreshold;
extern const int kHTTPPacketThreshold;

extern vector<Rule> all_rule_set;
extern vector<Rule>::iterator rule_iter;
extern vector<Rule>::iterator rule_iter_end;

extern map<string, string> domain_app;
extern vector<DomainKey> domain_table;

extern pcre* http_re;
extern pcre* rtsp_re;
extern pcre* ftp_re;

struct timeval GetStartTime();
float GetEndTime(struct timeval tpstart);

#endif