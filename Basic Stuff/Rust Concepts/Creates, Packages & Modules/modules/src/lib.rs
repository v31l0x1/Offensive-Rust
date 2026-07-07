mod list {


    pub struct Task {
        pub item: String
    }
    
    // pub mod things_todo{
    //     pub fn add_activity(){}
    //     fn update_activity(){}
    //     fn marked_completed() {}
    // }

    // mod items_completed{
    //     fn remove_task(){}
    //     fn move_back_todo(){}
    // }

}

mod things_todo;
use crate::things_todo::add_activity;
use things_todo::items_completed;
use things_todo::items_completed::test;

fn lets_add_task() {
    let task = list::Task {item: String::from("Task")};

    // list::things_todo::add_activity(); // relative path
 
    // crate::list::things_todo::add_activity(); //absolute path because we start at the root create

    things_todo::add_activity();

    add_activity();

    items_completed::remove_task();

    test::test();

}