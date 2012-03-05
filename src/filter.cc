#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include "./include/match_parser.h"
#include "./include/rule.h"
#include "./include/rule_set.h"
#include "./include/global.h"
#include "./include/nids.h"
#include "stdio.h"
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

bool omit_udp = false;

void tcp_callback(struct tcp_stream *ts, void **this_time_not_needed)
{
  if (ts->nids_state == NIDS_JUST_EST) { // New connection just be set
    ts->client.collect++;
      ts->server.collect++;
    ts->match_parser = new MatchParser(&ts->addr);
    return;
  }
  
  if (ts->nids_state == NIDS_CLOSE ||
      ts->nids_state == NIDS_TIMED_OUT ||
      ts->nids_state == NIDS_RESET) { // A connection will be closed
    // TODO: Send the result
    return;
  }
  
  if (ts->nids_state == NIDS_DATA) { // TCP data comes
    packet_id++;
    MatchParser* match_parser = (MatchParser*)ts->match_parser;
    Rule* now_rule = match_parser->get_now_rule();
    match_parser->set_packet_num();
    // we may never know what it is
    if (match_parser->get_never_know()) return;
    if (now_rule == NULL && match_parser->get_packet_num() > kTCPPacketThreshold) {
      match_parser->set_never_know();
      return;
    }
    if (ts->client_to_server) { // new data from client to server
      match_parser->set_payload(ts->server.data, ts->server.count_new); // WATCH: we do a lot of things here
    }
    else { // from server to client
      match_parser->set_payload(ts->client.data, ts->client.count_new); // WATCH: we do a lot of things here
    }
    
    if (match_parser->is_omit()) {
      match_parser->NowRuleMatch();
    }
    else if (match_parser->get_has_cache()) {
      if (!match_parser->ParserCacheMatch()) {
        match_parser->RuleSetMatch();
      }
    }
    else {
      match_parser->RuleSetMatch();
    }
    return;
  }
  
  return;
}

void udp_callback(struct tuple4 *addr, u_char *data, int len, struct ip *pkt)
{
  if (omit_udp) {
    return;
  }
  if (addr->dest == 53 || addr->source == 53) { // DNS Packet
    return;
  }
  MatchParser* match_parser = new MatchParser(addr);
  match_parser->set_protocol_name("UDP");
  match_parser->set_payload(data, len);
  match_parser->RuleSetMatch();
  return;
}

void InitAllRuleSet(vector<Rule>& all_rule_set)
{
  string rule_str;
  char filename[] = "../rules/new_final.rule";
  ifstream fin(filename);
  while (getline(fin, rule_str)) {
    if (rule_str.size() < 10 || rule_str[0] == '#') {
      continue;
    }
    Rule rule = Rule(rule_str);
    all_rule_set.push_back(rule);
  }
  printf("all %d rules in total\n", all_rule_set.size());
  rule_iter = all_rule_set.begin();
  rule_iter_end = all_rule_set.end();
}

unsigned long GetFileSize(char *filename)
{
  struct stat buf;
  if (stat(filename, &buf)<0) {
    return 0;
  }
  return (unsigned long)buf.st_size;
}

int main(int argc, char* argv[])
{
  InitAllRuleSet(all_rule_set);
  char static_filename[500];
  if (argc != 2) {
    strcpy(static_filename, "../pcap/sample.pcap");
  }
  else {
    strcpy(static_filename, argv[1]);
  }
  // de-comment next line to analyze online
  // nids_params.device = "eth0";
  nids_params.filename = static_filename; // if you want analyze online, comment this line
  nids_params.tcp_workarounds = true;

  if (!nids_init()) {
    printf("%s\n", nids_errbuf);
    exit(1);
  }
  
  nids_register_tcp((void *)tcp_callback);
  nids_register_udp((void *)udp_callback);
  struct timeval tpstart = GetStartTime();
  nids_run();
  float timeuse = GetEndTime(tpstart);
  printf("real use time is %f\n", timeuse);
  printf("speed is %fMbps\n", 8*(float)GetFileSize(static_filename)/(timeuse*1000*1000));
  return 0;
}
