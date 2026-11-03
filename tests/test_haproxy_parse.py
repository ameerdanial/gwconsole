"""Tests for parsing HAProxy "show info" and "show stat" output."""
from app.haproxy import parse_info, parse_stat

STAT = """# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail,req_rate,req_rate_max,req_tot,cli_abrt,srv_abrt,comp_in,comp_out,comp_byp,comp_rsp,lastsess,last_chk,last_agt,qtime,ctime,rtime,ttime,agent_status,agent_code,agent_duration,check_desc,agent_desc,check_rise,check_fall,check_health,agent_rise,agent_fall,agent_health,addr,cookie,mode
fe_https,FRONTEND,,,3,10,2000,100,5000,20000,0,0,1,,,,,OPEN,,,,,,,,,1,2,0,,,,0,5,0,9,,,,0,30,0,30,0,0,,4,9,60,,,0,0,0,0,,,,,,,,,,,,,,,,,,,,,http
be_web,web1,0,0,1,4,,40,2400,5300,,0,,0,0,0,0,UP,1,1,0,0,0,240,0,,1,3,1,,40,,2,1,,4,L7OK,200,1,0,40,0,0,0,0,,,,40,0,0,,,,,0,,,0,0,1,5,,,,Layer7 check passed,,2,3,4,,,,127.0.0.1:9001,,http
be_web,web2,0,0,0,2,,0,0,0,,0,,0,0,0,0,MAINT,1,1,0,0,1,30,30,,1,3,2,,0,,2,0,,0,L4CON,,0,0,0,0,0,0,0,,,,0,0,0,,,,,-1,,,0,0,0,0,,,,Layer4 connection problem,,2,3,0,,,,127.0.0.1:9002,,http
be_web,BACKEND,0,0,1,4,200,40,2400,5300,0,0,,0,0,0,0,UP,1,1,0,,0,240,0,,1,3,0,,40,,1,1,,4,,,,0,40,0,0,0,0,,,,40,0,0,0,0,0,0,0,,,0,0,1,5,,,,,,,,,,,,,,http
"""


def test_parse_stat_groups_servers_under_backends():
    d = parse_stat(STAT)
    assert [f["name"] for f in d["frontends"]] == ["fe_https"]
    be = d["backends"][0]
    assert be["name"] == "be_web" and be["status"] == "UP"
    assert [(s["name"], s["status"], s["addr"]) for s in be["servers"]] == [
        ("web1", "UP", "127.0.0.1:9001"), ("web2", "MAINT", "127.0.0.1:9002")]
    assert be["servers"][0]["check_status"] == "L7OK"


def test_parse_info():
    i = parse_info("Name: HAProxy\nVersion: 2.8.30\nMaxconn: 2000\nCurrConns: 3\n")
    assert i["Version"] == "2.8.30" and i["Maxconn"] == "2000"
