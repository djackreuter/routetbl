/* 
Inspired by reenz0h (twitter: @SEKTOR7net) from Windows Evasion course.
Basically a Rust port that uses WMI instead of the WinAPI
*/
use wmi::{WMIConnection, COMLibrary};
use serde::Deserialize;

fn main() {

    #[derive(Deserialize, Debug)]
    #[serde(rename = "Win32_IP4RouteTable")]
    #[allow(non_snake_case)]
    struct RouteTbl {
        Destination: String,
        Mask: String,
        NextHop: String,
        InterfaceIndex: i32,
        Type: u32,
        Protocol: u32,
        Age: i32,
        Metric1: i32
    }

    const MIB_IPROUTE_TYPE_OTHER: u32 = 1;
    const MIB_IPROUTE_TYPE_INVALID: u32 = 2;
    const MIB_IPROUTE_TYPE_DIRECT: u32 = 3;
    const MIB_IPROUTE_TYPE_INDIRECT: u32 = 4;

    const MIB_IPPROTO_OTHER: u32 = 1;
    const MIB_IPPROTO_LOCAL: u32 = 2;
    const MIB_IPPROTO_NETMGMT: u32 = 3;
    const MIB_IPPROTO_ICMP: u32 = 4;
    const MIB_IPPROTO_EGP: u32 = 5;
    const MIB_IPPROTO_GGP: u32 = 6;
    const MIB_IPPROTO_HELLO: u32 = 7;
    const MIB_IPPROTO_RIP: u32 = 8;
    const MIB_IPPROTO_IS_IS: u32 = 9;
    const MIB_IPPROTO_ES_IS: u32 = 10;
    const MIB_IPPROTO_CISCO: u32 = 11;
    const MIB_IPPROTO_BBN: u32 = 12;
    const MIB_IPPROTO_OSPF: u32 = 13;
    const MIB_IPPROTO_BGP: u32 = 14;
    const MIB_IPPROTO_NT_AUTOSTATIC: u32 = 10002;
    const MIB_IPPROTO_NT_STATIC: u32 = 10006;
    const MIB_IPPROTO_NT_NON_DOD: u32 = 10007;

    let wmi_conn: WMIConnection = WMIConnection::with_namespace_path("ROOT\\CIMv2", COMLibrary::new().unwrap()).unwrap();

    let routes: Vec<RouteTbl> = wmi_conn.query().unwrap();

    println!("Num entries: {}", routes.len());

    for (i, route) in routes.iter().enumerate() {
        println!("Route[{}] Dest IP: {}", i, route.Destination);
        println!("Route[{}] Subnet Mask: {}", i, route.Mask);
        println!("Route[{}] Next Hop: {}", i, route.NextHop);
        println!("Route[{}] Interface Index: {}", i, route.InterfaceIndex);

        match route.Type {
            MIB_IPROUTE_TYPE_OTHER => {
                println!("Route[{}] Type: other", i);
            },
            MIB_IPROUTE_TYPE_INVALID => {
                println!("Route[{}] Type: {} - invalid route", i, route.Type);
            },
            MIB_IPROUTE_TYPE_DIRECT => {
                println!("Route[{}] Type: {} - local route where next hop is final destination", i, route.Type);
            },
            MIB_IPROUTE_TYPE_INDIRECT => {
                println!("Route[{}] Type: {} - remote route where next hop is not final destination", i, route.Type);
            },
            _ => {
                println!("Route[{}] Type: {} - unknown type value", i, route.Type);
            }
        }

        match route.Protocol {
            MIB_IPPROTO_OTHER => {
                println!("Route[{}] Proto: {} - Other", i, route.Protocol);
            },
            MIB_IPPROTO_LOCAL => {
                println!("Route[{}] Proto: {} - local interface", i, route.Protocol);
            },
            MIB_IPPROTO_NETMGMT => {
                println!("Route[{}] Proto: {} - static route set through network management", i, route.Protocol);
            },
            MIB_IPPROTO_ICMP => {
                println!("Route[{}] Proto: {} - result of ICMP redirect", i, route.Protocol);
            },
            MIB_IPPROTO_EGP => {
                println!("Route[{}] Proto: {} - Exterior Gateway Protocol (EGP)", i, route.Protocol);
            },
            MIB_IPPROTO_GGP => {
                println!("Route[{}] Proto: {} - Gateway-to-Gateway Protocol (GGP)", i, route.Protocol);
            },
            MIB_IPPROTO_HELLO => {
                println!("Route[{}] Proto: {} - Hello protocol", i, route.Protocol);
            },
            MIB_IPPROTO_RIP => {
                println!("Route[{}] Proto: {} - Routing Information Protocol (RIP)", i, route.Protocol);
            },
            MIB_IPPROTO_IS_IS => {
                println!("Route[{}] Proto: {} - Intermediate System-to-Intermediate System (IS-IS) protocol", i, route.Protocol);
            },
            MIB_IPPROTO_ES_IS => {
                println!("Route[{}] Proto: {} - End System-to-Intermediate System (ES-IS) protocol", i, route.Protocol);
            },
            MIB_IPPROTO_CISCO => {
                println!("Route[{}] Proto: {} - Cisco Interior Gateway Routing Protocol (IGRP)", i, route.Protocol);
            },
            MIB_IPPROTO_BBN => {
                println!("Route[{}] Proto: {} - BBN Internel Gateway Protocol (IGP) using SPF", i, route.Protocol);
            },
            MIB_IPPROTO_OSPF => {
                println!("Route[{}] Proto: {} - Open Shortest Path First (OSPF) protocol", i, route.Protocol);
            },
            MIB_IPPROTO_BGP => {
                println!("Route[{}] Proto: {} - Border Gateway Protocol (BGP)", i, route.Protocol);
            },
            MIB_IPPROTO_NT_AUTOSTATIC => {
                println!("Route[{}] Proto: {} - special Windows auto static route", i, route.Protocol);
            },
            MIB_IPPROTO_NT_STATIC => {
                println!("Route[{}] Proto: {} - special Windows static route", i, route.Protocol);
            },
            MIB_IPPROTO_NT_NON_DOD => {
                println!("Route[{}] Proto: {} - special Windows static route not based on Internet standards", i, route.Protocol);
            },
            _ => {
                println!("Route[{}] Unknown proto", i);
            }
        }

        println!("Route[{}] Age: {}", i, route.Age);
        println!("Route[{}] Metric1: {}", i, route.Metric1);

        println!("\n");
    }
    
}
