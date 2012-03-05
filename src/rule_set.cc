#include "./include/rule.h"
#include "./include/rule_key.h"
#include "./include/rule_set.h"
#include "stdio.h"
#include <vector>
#include <string>

using namespace std;

RuleSet::RuleSet() {}
RuleSet::~RuleSet() {}

RuleSet::RuleSet(RuleKey rule_key)
{
	this->rule_key_ = rule_key;
}

void RuleSet::InitRuleSet()
{
	if (this->rule_key_.protocol == "HTTP" ||
			this->rule_key_.protocol == "RTSP") {
		this->http_like_ = true;
	}
	else {
		this->http_like_ = false;
	}
}