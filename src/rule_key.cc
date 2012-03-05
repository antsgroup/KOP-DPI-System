#include "./include/rule_key.h"
#include <string>

using namespace std;

bool operator< (const RuleKey &t, const RuleKey &s)
{
	return ((t.app_name < s.app_name) || 
					(t.app_name == s.app_name && t.has_domain < s.has_domain) ||
					(t.app_name == s.app_name && t.has_domain == s.has_domain && t.protocol < s.protocol));
}