#include "./include/rule.h"
#include "./include/rule_key.h"
#include "./include/global.h"
#include <iostream>
#include <sstream>
#include <string>
#include "stdlib.h"
#include "stdio.h"

using namespace std;
using pcrecpp::RE;

Rule::Rule() 
{
	this->match_type_ = -1;
}

Rule::~Rule() {}

template <class T> 
void ConvertFromString(T &value, const std::string &s) 
{
  std::stringstream ss(s);
  ss >> value;
}

// We only do it in HTTP packet, so ix must be 0
RegularExpression Rule::get_field_reg(string field) {
	int ix = 0;
	int field_pos = -1;
	for (int iy = 0; iy != this->protocol_vector_[ix].protocol_field.size(); ++iy) {
		if (this->protocol_vector_[ix].protocol_field[iy] == field) {
			field_pos = iy;
			break;
		}
	}
	if (field_pos == -1) {
		RegularExpression new_re;
		new_re.reg_expr_compile = NULL;
		return new_re;
	}
	return this->reg_expr_vector_[0][field_pos];
}

Rule::Rule(string raw_rule_string)
{
  int match_type;
  Business business;
	RuleKey rule_key;
	rule_key.has_domain = false;
  //string raw_rule_string = "0|Gmail@NewMail@Android@GmailClient|[HTTP:User-Agent,Host][HTTP:Host,URI]|[None][None]|['abc':13_15,'ggg':-1_-1]['def':-1_-1]";
  //string raw_rule_string = "1|Gmail@NewMail@Android|mail.google.com|[None][None][None]|[None][None]|[134][-136][138]";
  string match_type_str;
  match_type_str = raw_rule_string.substr(0, 1);
  sscanf(match_type_str.c_str(), "%d", &match_type);
  this->match_type_ = match_type;
	this->rule_type_ = false;
  string::size_type pos1, pos2, pos3, pos4, pos5, pos6;
  pos1 = raw_rule_string.find('@', 1);
  business.app = raw_rule_string.substr(2, pos1-2);
	rule_key.app_name = business.app;
	
	this->step_size_ = -100;
	
  pos1++;
  pos2 = raw_rule_string.find('@', pos1);
  business.behavior = raw_rule_string.substr(pos1, pos2-pos1);
  
  pos2++;
  pos1 = raw_rule_string.find('@', pos2);
  business.os = raw_rule_string.substr(pos2, pos1-pos2);
 
  pos1++;
  pos2 = raw_rule_string.find('|', pos1);
  business.agent = raw_rule_string.substr(pos1, pos2-pos1);
 
  this->business_ = business;

  // Protocol Field Parser
  pos2++;
  pos1 = raw_rule_string.find('|', pos2);
  string protocol_str = raw_rule_string.substr(pos2, pos1-pos2);
  pos3 = pos4 = 0;
  while (pos3 != protocol_str.size()-1) {
    pos3++;
    pos4 = protocol_str.find(']', pos3);
    string one_pro_str = protocol_str.substr(pos3, pos4-pos3);
		pos5 = pos6 = 0;
    pos6 = one_pro_str.find(':', pos5);
    Protocol protocol;
    protocol.protocol_name = one_pro_str.substr(pos5, pos6-pos5);
		rule_key.protocol = protocol.protocol_name;
		if (rule_key.protocol == "HTTP" || rule_key.protocol == "RTSP") {
			this->rule_type_ = true;
		}
    string one_field_str = one_pro_str.substr(pos6+1, one_pro_str.size()-pos6);
		if (one_pro_str.find("Host") != string::npos) {
			rule_key.has_domain = true;
		}
    while (pos5 != one_pro_str.size()-1) {
      pos6 = one_field_str.find(',', pos5);
      if (pos6 == string::npos) {
        protocol.protocol_field.push_back(one_field_str.substr(pos5, one_field_str.size()-pos5));
        break;
      }
      else {
        protocol.protocol_field.push_back(one_field_str.substr(pos5, pos6-pos5));
        if (pos6 != one_field_str.size()-1)
          pos6++;
        pos5 = pos6;
      }
    }
    this->protocol_vector_.push_back(protocol);
    if (pos4 != protocol_str.size()-1)
      pos4++;
    pos3 = pos4;
  }

  // DocodeType Parser
  pos1++;
  pos2 = raw_rule_string.find('|', pos1);
  string decode_type_str = raw_rule_string.substr(pos1, pos2-pos1);

  pos5 = pos6 = 0;
  while (pos5 != decode_type_str.size()-1) {
    pos5++;
    pos6 = decode_type_str.find(']', pos5);
    string one_decode_type = decode_type_str.substr(pos5, pos6-pos5);
    this->decode_type_vector_.push_back(one_decode_type);
    if (pos6 != decode_type_str.size()-1)
      pos6++;
    pos5 = pos6;
  }

  // RegExpr Parser
  pos2++;
  pos1 = raw_rule_string.size();
  string reg_seq_str = raw_rule_string.substr(pos2, pos1-pos2);

  if (!match_type) {
    pos3 = pos4 = 0;
    while (pos3 != reg_seq_str.size()-1) {
      pos3++;
      pos4 = reg_seq_str.find(']', pos3);
      string one_reg_str = reg_seq_str.substr(pos3, pos4-pos3);
      pos5 = pos6 = 0;
      vector<RegularExpression> reg_vec;
      while (pos5 != one_reg_str.size()-1) {
				int while_time = 0;
        pos5++;
        pos6 = one_reg_str.find(',', pos5);

        string one_one_reg_str = one_reg_str.substr(pos5, pos6-pos5);
        RegularExpression reg;
        string reg_expr;
        reg_expr = one_one_reg_str.substr(0, one_one_reg_str.find(':', 0)-1);
        int s, e;
        sscanf(one_one_reg_str.substr(one_one_reg_str.find(':', 0)+1, one_one_reg_str.find('_', 0)).c_str(), "%d", &s);
        sscanf(one_one_reg_str.substr(one_one_reg_str.find('_', 0)+1, one_one_reg_str.size()-1).c_str(), "%d", &e);
        reg.start = s;
        reg.end = e;
				
				const char *error;
				int erroffset;
				int ovector[30];
				reg.reg_expr_compile = pcre_compile(reg_expr.c_str(), PCRE_CASELESS, &error, &erroffset, NULL);
				reg.reg_expr = RE(reg_expr);
				if (reg.reg_expr_compile == NULL) {
					printf("PCRE compilation failed at offset %d: %s\n", erroffset, error);
					exit(0);
				}
        reg_vec.push_back(reg);
        if (pos6 == string::npos) {
          break;
        }
        if (pos6 != one_reg_str.size()-1)
          pos6++;
        pos5 = pos6;
				while_time++;
      }
      this->reg_expr_vector_.push_back(reg_vec);
      if (pos4 != reg_seq_str.size()-1)
        pos4++;
      pos3 = pos4;
    }
  }
  else {
    return;
  }
  
	this->rule_key_ = rule_key;
  this->step_size_ = this->protocol_vector_.size();
	// Here we build the domain_table automaticlly
	for (int ix = 0; ix != this->protocol_vector_.size(); ++ix) {
		for (int iy = 0; iy != this->protocol_vector_[ix].protocol_field.size(); ++iy) {
			if (this->protocol_vector_[ix].protocol_field[iy] == "Host") {
				string host = this->reg_expr_vector_[ix][iy].reg_expr.pattern();
				bool is_new = true;
				for (int ix = 0; ix != domain_table.size(); ++ix) {
					if (domain_table[ix].host.pattern() == host) {
						is_new = false;
						break;
					}
				}
				if (is_new) {
					pcrecpp::RE host_reg(host);
					DomainKey domain_key;
					domain_key.app = this->business_.app;
					domain_key.host = host_reg;
					domain_table.push_back(domain_key);
					//printf("%s : %s\n", host.c_str(), this->business_.app.c_str());
				}
				break;
			}
		}
	}
}