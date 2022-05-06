use std::{io::{self, stdin, BufRead, StdinLock, Lines, ErrorKind, stdout, Write}, net::{TcpListener, TcpStream}};
use connection::Connection;
use session::Session;

use crate::connection::{NegotiationError, CUSTOM_ALGO};

mod message;
mod connection;
mod session;

const PORT:u16 = 30522;

enum ConnectionChoice {
    Outbound,
    Incoming,
    Quit
}

enum MessagingChoice {
    Send,
    SendTime,
    Recieve,
    Disconnect
}

/*
TODOS: Most important first.
 - Fix security hole in key sending (again) ASAP.
 - Make the app actually usable
 - Make keys persistent (both mine and others').
 - Perhaps improve reading and writing making a function that writes the length then the data and a function that reads that information back beacuse I've written the same code like 1000 times.
 - Make message types an enum (this would be but i cba).
 - Make chunk sending not use .to_vec() which copies data and uses loads of RAM for large chunks.
 - MAYBE fix the horrific error system I have in place or let other people know how messy it is.
 */
fn main() {
    let mut using_port = PORT;
    let mut listener:Option<TcpListener> = None;
    while let None = listener {
        let l = TcpListener::bind(format!("0.0.0.0:{}", using_port));

        match l {
            Ok(l) => {
                listener = Some(l);
            },
            Err(e) => {
                let kind = e.kind();
                match kind {
                    io::ErrorKind::AddrInUse => {
                        using_port += 1; //Try port one above.
                    },

                    _ => {
                        panic!("Error: Failed to create listener: {:?}", kind);
                    }
                }
            },
        }
    }

    let listener = listener.unwrap();
    
    println!("Listening on port {:?}.", using_port);

    let stdin = stdin();
    let mut line_iter = stdin.lock().lines();

    'main: loop {
        let choice = menu_choices(&mut line_iter, "Welcome to P2PEM. Please choose an option below.", &[
            ("Connect to another client.", &ConnectionChoice::Outbound), 
            ("Recieve an incoming connection.", &ConnectionChoice::Incoming), 
            ("Exit the program.", &ConnectionChoice::Quit)]);
        
        let conn: Result<Connection, NegotiationError>;

        match choice {
            ConnectionChoice::Outbound => {
                let out_conn = connect_ip(&mut line_iter);
                match out_conn {
                    Ok(c) => {
                        println!("Established connection. Attempting to negotiate.");
                        conn = Connection::negotiate(c, false);
                    },
                    Err(e) => {
                        println!("Failed to establish connection: {:?}", e);
                        continue 'main;
                    },
                }
            },
            ConnectionChoice::Incoming => {
                let rec_conn = listener.accept();
                match rec_conn {
                    Ok((c, addr)) => {
                        println!("Accepting connection from: {:?}", addr);
                        conn = Connection::negotiate(c, true);
                    },
                    Err(e) => {
                        println!("Connection failed: {:?}", e);
                        continue 'main; //Go back to the start
                    },
                }
            },
            ConnectionChoice::Quit => {
                println!("Goodbye.");
                break 'main;
            },
        }

        let mut session: Session;
        match conn {
            Ok(conn) => {
                session = Session::new(conn);
            },
            Err(err) => {
                println!("Failed to negotiate connection. Error: {:?}", err);
                continue 'main;
            },
        }

        'connection: loop {
            let mut choices = vec![
                ("Send a message.", &MessagingChoice::Send),
                ("Recieve a message.", &MessagingChoice::Recieve), 
                ("Quit", &MessagingChoice::Disconnect)];

            if session.conn.has_msg_capability(CUSTOM_ALGO) {
                choices.insert(1, ("Send the current time.", &MessagingChoice::SendTime))
            }

            let message_choice = menu_choices(&mut line_iter, "What would you like to do now?", &choices);
    
            match message_choice {
                MessagingChoice::Send => {
                    let msg = take_message(&mut line_iter);
                    match session.send_text_msg(&msg) {
                        Ok(_) => {},
                        Err(err) => {
                            println!("Failed to send message: {:?}. Disconnecting.", err);
                            break 'connection;
                        },
                    }

                },
                MessagingChoice::SendTime => {
                    match session.send_date_message(){
                        Ok(_) => {},
                        Err(err) => {
                            println!("Failed to send date: {:?}. Disconnecting.", err);
                            break 'connection;
                        },
                    }
                },
                MessagingChoice::Recieve => {
                    let possible_msg = session.get_next_message();
                    match possible_msg {
                        Ok(msg) => {
                            println!("THEM: {}", msg);
                        },
                        Err(err) => {
                            println!("Failed to recieve message: {:?}. Disconnecting.", err);
                            break 'connection;
                        },
                    }
                },
                MessagingChoice::Disconnect => break 'connection,
            }

        }
    }

}

fn menu_choices<'a, T>(iter: &mut Lines<StdinLock>, prompt: &str, choices: &'a [(&str, &T)]) -> &'a T{
    loop {
        println!("{}", prompt);
        for (i, (c, _)) in choices.iter().enumerate() {
            println!("\t{0}: {1}", i, *c);
        }

        let line = iter.next();
        if let Some(line) = line {
            match line {
                Ok(opt) => {
                    let possible_choice = opt.parse::<usize>();
                    match possible_choice {
                        Ok(choice) => {
                            if choice < choices.len() {
                                return choices[choice].1;
                            } else {
                                println!("Please enter a valid choice.");
                            }
                        },
                        Err(_) => {
                            println!("Please enter a number that corresponds to a choice.");
                        },
                    }
                },
                Err(_) => {
                    println!("Failed to read line! Please try again.");
                },
            }
        }
    }
}

fn connect_ip(lines: &mut Lines<StdinLock>) -> io::Result<TcpStream> {
    loop {
        println!("Please enter an IP address to connect to.");
        let line = lines.next();
        if let Some(line) = line {
            match line {
                Ok(possible_ip) => {
                    let conn = TcpStream::connect(possible_ip);
                    match conn {
                        Ok(conn) => return Ok(conn),
                        Err(err) => {
                            let kind = err.kind();
                            match kind {
                                ErrorKind::InvalidInput => {
                                    println!("Please enter a valid IP address.");
                                    continue; //Reset loop
                                }
                                _ => {
                                    return Err(err);
                                }
                            }
                        },
                    }
                },
                Err(_) => println!("Failed to read line."),
            }
        }
    }
}

fn take_message(lines: &mut Lines<StdinLock>) -> String{
    loop {
        print!("What's on your mind?\nYOU: ");
        let _ = stdout().flush();
        let line = lines.next();
        if let Some(line) = line {
            match line {
                Ok(line) => {
                    return line;
                },
                Err(_) => {
                    println!("An error occured trying to read your message. Please try again.");
                },
            }
        }
    }
}
