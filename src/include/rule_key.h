/*----------------------*/
/*	Create by Toney Lee */
/*	2012.2.25					*/
/*----------------------*/
#ifndef HOLMESII_RULE_KEY_H_
#define HOLMESII_RULE_KEY_H_

#include <string>
//#include "global.h"
using namespace std;

struct RuleKey {
	string app_name;
	bool has_domain;
	string protocol;
	friend bool operator< (const RuleKey &t, const RuleKey &s);
};

#endif