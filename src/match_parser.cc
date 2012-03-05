#include "./include/match_parser.h"
#include "./include/rule.h"
#include "./include/rule_set.h"
#include "./include/global.h"
#include "./include/pcrecpp.h"
#include <vector>
#include <string>
#include <map>
#include <sstream> 
#include "stdio.h"
#include "string.h"
#include <iostream>

using namespace std;
using pcrecpp::RE;

#define OVECCOUNT 30

MatchParser::MatchParser() {}

MatchParser::MatchParser(struct tuple4* addr)
{
	this->app_name_ = "UNTOUCHED";
	this->has_cache_ = false;
	this->now_rule_ = NULL;
	this->payload_ = NULL;
	this->payload_len_ = 0;
	this->protocol_name_ = "UNKNOWN";
	this->packet_num_ = 0;
	this->http_set_ = false;
	this->addr_ = addr;
	this->rule_set_ = NULL;
	this->never_know_ = false;
	this->omit_ = false;
	this->http_like_ = false;
}

MatchParser::~MatchParser() {}

void MatchParser::set_payload(char* payload, int len)
{
	 this->payload_len_ = len;
	 this->payload_ = payload;
	 this->SetProtocol();
}

void MatchParser::set_payload(u_char* payload, int len)
{
	this->payload_len_ = len;
	this->payload_ = (char*)payload;
}

bool MatchParser::HTTPLikeMatch(Rule* rule)
{
	if (this->protocol_name_ != "HTTP" && this->protocol_name_ != "RTSP") {
		//printf("%s protocol happens in HTTP Like match\n", this->protocol_name_.c_str());
		//printf("the 3tsc set protocol is %s\n", this->conn_tuple_->get_rule_set()->get_rule_key().protocol.c_str());
		//printf("source is %d, dest is %d\n", this->addr_->source, this->addr_->dest);
		//printf("The lost tcp segment may cause it for it has the same 3-tuple with a http 3tsc set, but it didn't get a http header\n");
		//printf("we should abandon packets like this.\n\n");
		return false;
	}
	int ix = 0;
	Protocol proto = rule->get_protocol_vector()[ix];
	vector<RegularExpression> re_vec = rule->get_reg_expr_vector()[ix];
	for (int iy=0; iy!=proto.protocol_field.size(); ++iy) {
		string field = proto.protocol_field[iy];
		string value = "";
		char* value_char;
		if (field != "Decode") {
			value = this->http_field_[field];
			if (value.size() < 2) {
				return false;
			}
			value_char = const_cast<char*>(value.c_str());
		}
		else {
			// TODO: Decode function
		}
		if (this->PCREMatch(re_vec[iy].reg_expr_compile, value_char, value.size())) continue;
		else {
			//printf("not match, value is %s, pattern is %s\n", value_char, re_vec[iy].reg_expr.pattern().c_str());
			return false;
		}
	}
	return true;
}

bool MatchParser::TCPLikeMatch(Rule* rule, int step)
{
	int ix = step - 1;
	Protocol proto = rule->get_protocol_vector()[ix];
	int size_end = proto.protocol_field.size();
	vector<RegularExpression> re_vec = rule->get_reg_expr_vector()[ix];
	for (int iy=0; iy!=size_end; ++iy) {
		string field = proto.protocol_field[iy];
		if (field != "None") {
			stringstream str;
			int int_value;
			str << re_vec[iy].reg_expr.pattern();
			str >> int_value;
			if (field == "SRC_PORT") {
				if (this->addr_->source == int_value) {
					continue;
				}
				else {
					return false;
				}
				break;
			}
			else if (field == "DST_PORT") {
				if (this->addr_->dest == int_value) {
					continue;
				}
				else {
					return false;
				}
				break;
			}
			else if (field == "Length") {
				if (this->payload_len_ == int_value) {
					continue;
				}
				else {
					return false;
				}
				break;
			}
			else { // DEBUG STATEMENT
				cout << rule->get_business().app << " " << rule->get_business().behavior << " " << rule->get_business().os << endl;
				printf("Something wrong with the TCP fields %s.\n", field.c_str());
				return false;
			}
		}
		else {
			int len = re_vec[iy].end - re_vec[iy].start;
			len = !len ? this->payload_len_ : len+1;
			if (this->PCREMatch(re_vec[iy].reg_expr_compile, this->payload_, len)) {
				continue;
			}
			else {
				return false;
			}
			break;
		}
	}
	return true;
}

bool MatchParser::PCREMatch(pcre* re, char* content, int len)
{
	const char *error;
  int erroffset;
  int ovector[OVECCOUNT];
  int rc;

  rc = pcre_exec(re, NULL, content, len, 0, 0, ovector, OVECCOUNT);
  if (rc < 0) {
    return 0; // Pattern not matched
  }
  return 1; // Successfully matched
}

void MatchParser::NowRuleMatch()
{
	// MARK: We may only need to add the bytes here
	// for the http flow will only be matched for one packet once.
	// TODO: Update result table
	return;
}

bool MatchParser::ParserCacheMatch()
{
	vector<ParserCacheNode>::iterator iter = this->parser_cache_.begin();
	if (!this->http_like_) {
		bool is_match = false;
		for (; iter != this->parser_cache_.end(); ++iter) {
			if (this->TCPLikeMatch(iter->rule, iter->step)) {
				if (iter->step == iter->rule->get_step_size()) { // Clear Cache
					this->parser_cache_.clear();
					this->has_cache_ = false;
					// TODO: Update result table
				}
				else { // Update Cache
					iter->step++;
				}
				return true; // MARK:
										 // i'm not very sure that whether we should
								     // parse every TCP rule even there's one which has been
								     // matched for 1 or more step.
			}
		}
		return is_match;
	}
	else { // DEBUG STATEMENT
		printf("How can there be a http rule which matches more than one packet\n");
	}
	return false;
}

void MatchParser::PostMatch(Rule* rule)
{
	this->now_rule_ = rule;
	if (rule->get_rule_type()) { // TODO: Not every Http connection can be omit
															 // even it has been matched.
		this->omit_ = true;
	}
	return;
}

void MatchParser::RuleSetMatch()
{
	vector<Rule>::iterator iter = rule_iter;
	vector<Rule>::iterator iter_end = rule_iter_end;
	if (this->http_like_) {
		if (this->packet_num_ >= kHTTPPacketThreshold) {
			this->never_know_ = true;
			return;
		}
		for (; iter != iter_end; ++iter) {
			if (this->protocol_name_ != iter->get_protocol_vector()[0].protocol_name) {
				continue;
			}
			if (this->HTTPLikeMatch(&(*iter))) {
				// TODO: Update result table
				printf("%d got a match %s@%s\n", packet_id, iter->get_business().app.c_str(), iter->get_business().behavior.c_str());
				this->PostMatch(&(*iter)); // Update 3TSC set's rule set
				return;
			}
		}
		return;
	}
	else {
		if (this->packet_num_ >= kTCPPacketThreshold) {
			this->never_know_ = true;
			return;
		}
		for (; iter != iter_end; ++iter) {
			if (this->protocol_name_ != iter->get_protocol_vector()[0].protocol_name) {
				continue;
			}
			if (this->TCPLikeMatch(&(*iter), 1)) {
				if (1 == iter->get_step_size()) {
					if (has_cache_) { // Clear cache
						this->parser_cache_.clear();
						this->has_cache_ = false;
					}
					// TODO: Update result table
					this->PostMatch(&(*iter)); // Update 3TSC set's rule set
					return;
				}
				else { // Update Cache
						ParserCacheNode new_node;
						new_node.rule = &(*iter);
						new_node.step = 2;
						this->parser_cache_.push_back(new_node);
						this->has_cache_ = true;
				}
				return; // MARK:
								// i'm not very sure that whether we should
								// parse every TCP rule even there's one which has been
								// matched for 1 or more step.
			}
		}
	}
	return;
}

void MatchParser::AnalyzeProtocol()
{
	if (this->http_like_ && !this->http_set_) {
		this->SetHTTPField();
	}
	return;
}

void MatchParser::SetProtocol()
{
	if (this->protocol_name_ != "UNKNOWN") {
		this->AnalyzeProtocol();
		return;
	}
	// First time met this connection
	if (this->PCREMatch(http_re, this->payload_, this->payload_len_)) {
		//printf("http packet\n");
		this->protocol_name_ = "HTTP";
		this->SetHTTPField();
		this->set_http_like();
	}
	else if (this->PCREMatch(rtsp_re, this->payload_, this->payload_len_)) {
		printf("rtsp packet\n");
		this->protocol_name_ = "RTSP";
		this->SetHTTPField();
		this->set_http_like();
	}
	else if (this->PCREMatch(ftp_re, this->payload_, this->payload_len_)) {
		printf("ftp packet\n");
		this->protocol_name_ = "FTP";
	}
	else {
		//printf("tcp packet\n");
		this->protocol_name_ = "TCP";
	}
	this->AnalyzeProtocol();
	return;
}

void MatchParser::SetHTTPField()
{
	string field;
	string whole(this->payload_, 0, this->payload_len_-1);
	string header = whole.substr(0, whole.find("\r\n\r\n"));
	//printf("header is %s\n", header.c_str());
	field = "Method";
	this->http_field_[field] = header.substr(0, header.find(" "));
	//printf("Method : %s\n", http_field_[field].c_str());
	field = "URI";
	this->http_field_[field] = header.substr(header.find(" ")+1, header.find("\r\n")-header.find(" "));
	//printf("URI : %s\n", http_field_[field].c_str());
	int now_start = 0;
	now_start = header.find("\r\n", now_start) + 2;
	while (now_start != string::npos) {
		string value;
		int now_end = header.find("\r\n", now_start) - now_start + 1;
		string one_line = header.substr(now_start, now_end-1);
		field = one_line.substr(0, one_line.find(": "));
		//printf("field is %s\n", field.c_str());
		int temp_start = one_line.find(": ");
		if (temp_start == string::npos) {
			break;
		}
		temp_start += 2;
		value = one_line.substr(temp_start);
		//printf("value is %s\n", value.c_str());
		if (value.size() >= 2) {
			this->http_field_[field] = value;
			//printf("%s : %s\n", field.c_str(), http_field_[field].c_str());
		}
		now_start = header.find("\r\n", now_start);
		if (now_start == string::npos) {
			break;
		}
		else {
			now_start += 2;
		}
	}
	this->http_set_ = true;
}
