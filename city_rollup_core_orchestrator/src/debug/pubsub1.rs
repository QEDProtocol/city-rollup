use city_common::{
    cli::args::{L2WorkerArgs, OrchestratorArgs},
    logging::debug_timer::DebugTimer,
};
use redis::Commands;

pub fn run_pub_sub_demo_1(args: OrchestratorArgs) {
    let client = redis::Client::open(args.redis_uri).unwrap();
    let mut connection = client.get_connection().unwrap();

    let mut pubsub = connection.as_pubsub();
    pubsub.subscribe("orchestrator_input").unwrap();
    let mut timer = DebugTimer::new("orchestrator_recv");
    let mut count = 0i32;
    timer.lap("starting orchestrator");
    let msg = pubsub.get_message().unwrap();
    timer.lap("started messages");
    let start_time = timer.start_time;
    loop {
        let msg = pubsub.get_message().unwrap();
        let payload: String = msg.get_payload().unwrap();
        count += 1;
        if payload.eq("stop_orchestrator") {
            break;
        }
    }
    timer.lap("stopped orchestrator");
    let end_time = timer.start_time;
    println!("Received {} messages", count);
    println!("Total time: {:?}", end_time - start_time);
    println!(
        "Average time: {:?}ms per messsage",
        (end_time - start_time).as_millis() as f64 / (count as f64)
    );
}

pub fn run_pub_sub_demo_1_client(args: L2WorkerArgs) {
    let client = redis::Client::open(args.redis_uri).unwrap();
    let mut connection = client.get_connection().unwrap();
    for _ in 0..100000 {
        let cmd: i32 = connection.publish("orchestrator_input", "hellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohellohello").unwrap();
    }
    let cmd: i32 = connection
        .publish("orchestrator_input", "stop_orchestrator")
        .unwrap();
}
