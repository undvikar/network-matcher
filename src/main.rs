mod receive;
mod trace;
mod structs;
mod matcher;
mod output;


use crate::structs::{
    traffic_history::TrafficHistory,
    delay_queue::DelayQueue,
    unmatched::UnmatchedEvents,
    output::Config,
};

use crate::matcher::matching;
use crate::output::output;

use std::thread;
use std::io;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use crossbeam_channel::unbounded;
use clap::{Arg, Command};
use parking_lot::{Mutex, RwLock};
use std::time::Duration;
use pnet::datalink;

fn main() {
    // Arguments parser.
    let matches = Command::new("Matcher")
        .arg(Arg::new("threads")
            .short('t')
            .long("threads")
            .takes_value(true)
            .help("Number of threads to use for matching."))
        .arg(Arg::new("quiet")
            .short('q')
            .long("quiet")
            .help("Only output final statistics."))
        .arg(Arg::new("clean")
            .short('c')
            .long("clean")
            .takes_value(true)
            .help("Set history and unmatched events to be cleaned every <arg> seconds. Defaults to 3."))
        .arg(Arg::new("timeout-history")
            .long("timeout-history")
            .takes_value(true)
            .help("Set timeout for frames in the traffic history to <arg> seconds. Defaults to 5."))
        .arg(Arg::new("timeout-unmatched")
            .long("timeout-unmatched")
            .takes_value(true)
            .help("Set timeout for events in the queue of unmatched events to <arg> seconds. Defaults to 2."))
        .arg(Arg::new("buffer-time")
            .long("buffer-time")
            .takes_value(true)
            .help("Set time for how long frames will be buffered in the delay queue to <arg> microseconds. Defaults to 200000."))
        .arg(Arg::new("interface")
            .short('i')
            .long("interface")
            .takes_value(true)
            .help("Specify a single interface to capture on."))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .takes_value(true)
            .help("Output results to the specified file in CSV format."))
        .arg(Arg::new("separator")
            .short('s')
            .long("separator")
            .takes_value(true)
            .requires("output")
            .help("Specify a char to separate values in the CSV output file. Defaults to a comma."))
        .get_matches();

    let interface = if !matches.is_present("interface") {
        None
    } else {
        let if_name = matches.value_of("interface").unwrap();
        let all_ifaces = datalink::interfaces();
        let iface = match all_ifaces.iter().find(|i| i.name == if_name) {
            Some(i) => i.clone(),
            None => {
                eprintln!("Specified interface does not exist!");
                std::process::exit(1);
            }
        };
        Some(iface)
    };
    let outputfile = if !matches.is_present("output") {
        None
    } else {
        // First check if file already exists so we don't overwrite it by accident.
        let name = matches.value_of("output").unwrap();
        if Path::new(name).exists() {
            println!("Specified output file exists! Overwrite? (yes/no)");
            let mut buf = String::new();
            match io::stdin().read_line(&mut buf) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("Error reading input: {}", e);
                    std::process::exit(1);
                },
            }
            match buf.trim() {
                "yes" => (),
                "no" => std::process::exit(0),
                _ => std::process::exit(1),
            }
        }
        // Create output file.
        let f = match File::create(name) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Error creating file: {}", e);
                std::process::exit(1);
            }
        };
        let sep = if !matches.is_present("separator") {
            ','
        } else {
            matches.value_of("separator").unwrap().parse().unwrap()
        };
        Some((f, sep))
    };

    let num_match_threads: u32 = matches.value_of("threads").unwrap_or("1").parse().unwrap();
    let quiet: bool = matches.is_present("quiet");

    let output_conf = Config {
        quiet: quiet,
        output_file: outputfile,
    };
    // Duration takes u64
    let timeout_history: u64 = matches.value_of("timeout-history").unwrap_or("5").parse().unwrap();
    let timeout_unmatched: u64 = matches.value_of("timeout-unmatched").unwrap_or("2").parse().unwrap();
    let clean: u64 = matches.value_of("clean").unwrap_or("3").parse().unwrap();
    let buffer_time: u64 = matches.value_of("buffer-time").unwrap_or("200000").parse().unwrap();

    let traffic_history = Arc::new(TrafficHistory::new(timeout_history));
    let delay_queue = Arc::new(Mutex::new(DelayQueue::new(buffer_time)));
    let unmatched_events = Arc::new(RwLock::new(UnmatchedEvents::new(timeout_unmatched)));
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = vec![];


    // References for the main matcher thread.
    let history = Arc::clone(&traffic_history);
    let dq = Arc::clone(&delay_queue);
    let unmatched = Arc::clone(&unmatched_events);
    let unmatched_trace = Arc::clone(&unmatched_events);
    let rc_dq = Arc::clone(&delay_queue);
    let s = Arc::clone(&stop);

    // Stop indicators for output, trace, and receiver threads.
    let st = Arc::clone(&stop);
    let sto = Arc::clone(&stop);
    let stopp = Arc::clone(&stop);
    // Channel for sending packets from matcher threads to output thread.
    let (tx, rx)= unbounded();



    // Create additional matcher threads according to command line arguments.
    for _ in 0..num_match_threads - 1 {
        let hist = Arc::clone(&traffic_history);
        let delay_q = Arc::clone(&delay_queue);
        let unmatched_ev = Arc::clone(&unmatched_events);
        let transmit = tx.clone();
        let halt = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            matching(hist, delay_q, unmatched_ev, transmit, &halt, false, None);
        });
        handles.push(handle);
    }

    // Create main matcher thread.
    let main_matcher = thread::spawn(move || {
        matching(history, dq, unmatched, tx, &s, true, Some(Duration::from_secs(clean)));
    });
    
    // Output thread.
    let output = thread::spawn(move || {
        match output(rx, &st, output_conf) {
            Err(_) => eprintln!("Channel closed"),
            _ => (),
        }
    });

    // Kernel thread.
    let tracer = thread::spawn(move || {
        trace::trace(&unmatched_trace, &sto);
    });

    // Receiver thread(packet sniffer).
    let rc = thread::spawn(move || {
        receive::receive(&rc_dq, &stopp, interface);
    });

    handles.push(output);
    handles.push(main_matcher);
    handles.push(tracer);
    handles.push(rc);

    // Stop if we receive Ctrl-C.
    ctrlc::set_handler(move || {
        stop.swap(true, Ordering::Relaxed);
    })
    .expect("Error setting ctrl-c handler");

    for handle in handles {
        handle.join().unwrap();
    }
}
