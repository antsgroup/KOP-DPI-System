/*----------------------*/
/*	Create by Toney Lee */
/*	MOE Lab XJTU			  */
/*	2011.11.26					*/
/*----------------------*/
#ifndef HOLMESII_MATCH_PARSER_H_
#define HOLMESII_MATCH_PARSER_H_

#include <string>
#include <vector>
#include <map>
#include "nids.h"
#include "pcre.h"

using namespace std;

class Rule;
class RuleSet;

struct ParserCacheNode {
	int step;
	Rule* rule;
};

class MatchParser {
 public:
  MatchParser();
	MatchParser(struct tuple4* addr);
	~MatchParser();
	inline Rule* get_now_rule() {return this->now_rule_;}
	inline RuleSet* get_rule_set() {return this->rule_set_;}
	inline string get_app_name() {return this->app_name_;}
	inline string get_protocol_name() {return this->protocol_name_;}
 	inline bool get_has_cache() {return this->has_cache_;}
	inline int get_packet_num() {return this->packet_num_;}
	inline string get_http_field(string field) {return this->http_field_[field];}
	inline bool get_never_know() {return this->never_know_;}
	inline bool is_omit()	{return this->omit_;}
	
	void set_packet_num() {this->packet_num_++;}
	void set_rule_set(RuleSet* rule_set) {this->rule_set_ = rule_set;}
	void set_now_rule(Rule * now_rule) {this->now_rule_ = now_rule;}
	void set_app_name(string app_name) {this->app_name_ = app_name;}
	void set_protocol_name(string protocol_name) {this->protocol_name_ = protocol_name;}
	void set_payload(char* payload, int len);
	void set_payload(u_char* payload, int len);
	void set_never_know() {this->never_know_ = true;}
	void set_http_like() {this->http_like_ = true;}
	
	void RuleSetMatch(); // Match the rules in the rule set
	void NowRuleMatch(); // Match now rule
	bool ParserCacheMatch(); // Match the rules in parser cache if not empty
 
 private:
  Rule* now_rule_; // The rule which just be matched for this connection
	RuleSet* rule_set_; // The suitable rule set for this connection
	vector<ParserCacheNode> parser_cache_; // Cache the rules which are in certain match steps
	bool has_cache_; // True if parser cache is not empty
	
	string app_name_;		// Application name for this connection which will be 
											// 'UNTOUCHED' if it is an new connection, 
										  // 'UNKNOWN' if it at least match one packet but still not match one rule.
	string protocol_name_; // HTTP, TCP, UDP, RTSP, etc.
	char* payload_; // the payload
	int payload_len_; // length of the payload
	struct tuple4* addr_;
	int packet_num_; // packet number of this connection
	map<string, string> http_field_;
	bool http_like_;
	bool http_set_;
	bool never_know_;
	bool omit_;
	// TODO: More rule match function here
	
	void SetHTTPField();
	void SetProtocol(); // Detect protocol name
	void AnalyzeProtocol(); // Analyze the protocol tree
	bool HTTPLikeMatch(Rule* rule);
	bool TCPLikeMatch(Rule* rule, int step);
	bool PCREMatch(pcre* re, char* content, int len);
	void PostMatch(Rule* rule);
	
	string DecodePayload(Rule* rule);
};

#endif
