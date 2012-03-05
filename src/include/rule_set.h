/*----------------------*/
/*	Create by Toney Lee */
/*	2012.2.25					*/
/*----------------------*/
#ifndef HOLMESII_RULE_SET_H_
#define HOLMESII_RULE_SET_H_

#include <vector>
#include "rule_key.h"
#include "rule.h"
#include "pcrecpp.h"
#include "pcre.h"

class Rule;
struct RuleKey;
struct Tuple3RuleKey;

using namespace std;

struct RuleTreeNode {
	string field;
	pcrecpp::RE reg;
	pcre* reg_compile;
	bool omit;
	vector<Rule*> rule_vector;
	vector<Rule> real_vector;
	Rule default_rule;
	RuleTreeNode* next_node;
	RuleTreeNode* next_layer;
};

class RuleSet {
 public:
	RuleSet();
	RuleSet(RuleKey rule_key);
	~RuleSet();
	void InitRuleSet();
	inline bool get_http_like() {return this->http_like_;}
	inline RuleKey get_rule_key() {return this->rule_key_;}
	inline vector<Rule>& get_rule_vector() {return this->rule_vector_;}
	
	inline void PushBack(Rule new_rule) {this->rule_vector_.push_back(new_rule);}
	inline void PushBack(Rule* new_rule) {this->rule_vector_ptr_.push_back(new_rule);}
	
 protected:
	vector<Rule*> rule_vector_ptr_;
	RuleTreeNode* head_layer_;
	vector<string> field_layer_;
	
 private:
	RuleKey rule_key_;
	vector<Rule> rule_vector_;
	bool http_like_;
};

#endif