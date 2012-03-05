/*----------------------*/
/*	Create by Toney Lee */
/*	MOE Lab XJTU			  */
/*	2011.11.26					*/
/*----------------------*/
#ifndef HOLMESII_RULE_H_
#define HOLMESII_RULE_H_

#include "rule_key.h"
#include "pcre.h"
#include "pcrecpp.h"
#include <vector>

using namespace std;

struct DomainKey {
	string app;
	pcrecpp::RE host;
};

struct Business {
	string app;				// Application Name (Sina_Weibo, Browser, etc.)
	string behavior;	// Behavior Name (Login, ViewPic, etc.)
	string agent;			// Client Name (WeiboClient, Opera, etc.)
	string os;				// OS Name (Android, iOS, Symbian, etc.)
};

struct Protocol {
	string protocol_name;
	vector<string> protocol_field;
};

struct RegularExpression {
	pcre* reg_expr_compile;
	pcrecpp::RE reg_expr;
	int start;
	int end;
};

class Rule {
 public:
	Rule();
	Rule(string raw_rule_string);
	~Rule();
	
	RegularExpression get_field_reg(string field);
	inline int get_match_type() {return this->match_type_;}
	inline bool get_rule_type() {return this->rule_type_;}
	inline RuleKey get_rule_key() {return this->rule_key_;}
	inline Business get_business() {return this->business_;}
	inline string get_domain_name() {return this->domain_name_;}
	inline vector<string> get_decode_type_vector() {return this->decode_type_vector_;}
	inline vector<Protocol> get_protocol_vector() {return this->protocol_vector_;}
	inline vector< vector<RegularExpression> > get_reg_expr_vector() {return reg_expr_vector_;}
	inline int get_step_size() {return this->step_size_;}
 private:
	int match_type_;
	bool rule_type_;	// True if the rule is HTTP like
	RuleKey rule_key_;
	Business business_;
	string domain_name_;
	int step_size_; // total step which should equal to the size of the protocol vector 
	vector<string> decode_type_vector_;
	vector<Protocol> protocol_vector_;
	vector< vector<RegularExpression> > reg_expr_vector_;
};

#endif