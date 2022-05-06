# bouncer

One day I realized that my server hadn't received updates in years, and given the likelyhood that attempting to update it would probably brick it, I really didn't want to.  However, every now and then, people find vulnerabilities in things like SSH, which is why there's a new IP trying to connect to it every 30 seconds.  So I needed to do something before the next vulnerability is discovered.

This is the idea behind what is known as "port knocking" but I've always thought that port knocking is dumb.  At the core of it is the idea that it's impossible to write a service that can accept a password and verify it without writing some kind of exploitable code, and so we're just going to watch attempted port connections instead.  That or the idea is that the server is going to fake out attackers by pretending it has no active services at all.  I don't know, but whatever the idea was, it results in the user getting no feedback as to whether authentication was successful, and it essentially transmits the "password" in plain text.

The goal of this project is to authenticate with an encrypted password, tell the user whether authentication was successful, allow the user access to other services on the server, and do it all with a program that's short and simple enough that people can read it and say "there's nothing exploitable in here."

## components

The project consists of four tools:

**bouncer-passwd** -- This allows you to type in the password and it saves it to `/etc/bouncer/passwd`.

**bouncer-server** -- This accepts requests from remote clients, authenticates them, and if successful, executes `/etc/bouncer/whitelist` which is expected to be a script that will configure your firewall to allow the IP address to access other services.

**bouncer-client** -- This contacts a server, receives a challenge, replies with the response, and then tells you whether the server accepted the password or not.

**windows-client.exe** -- Sometimes people SSH from Windows for some reason and need to get that port open.

Of the four, obviously bouncer-server is the one we're most concerned about being non-exploitable.  As such, I've added the most comments to its source code and tried to write it in the clearest and most obviously-correct way that I can.  At the moment of writing this, it is 256 lines total, including comments and blank lines.  Hopefully it's simple enough that people will read it and, if I've fucked anything up, report it, so that someday it's a totally bug-free program.

For now though, I'm the only one I know has looked at the code, so IDK if you should count on this program to be 100% bug-free yet.  Also, I haven't really put any thought into how to run it as a non-root user, though I expect it's possible without any changes.  I can only say that I trust that this code is bug-free more than I trust that there won't be any bugs discovered in SSH's user authentication in the future.  Obviously you have to use it at your own risk, but since server.c is only 256 lines, hopefully you can verify its security yourself.

## usage

Compile the linux utilities with `./compile` and the windows client with `./windows`.

Create folder `/etc/bouncer` and inside it create a `/etc/bouncer/whitelist` script.  When `bouncer-server` authenticates an IP address, it will call this script with the IP address as an argument and this script should add the IP address to your firewall rules to allow the IP address to access the protected services.  There's are example scripts in the `examples` folder.  Be sure to read the `notes.txt` in that folder.

Use `bouncer-passwd` to set the password you want to use, which will be encrypted and written to `/etc/bouncer/password`.

Run `bouncer-server`.  It will read `/etc/bouncer/password` once (so restart it if you change the password), listen and respond to packets, and report what it's doing to stdout which may be helpful for debugging.

Then use `bouncer-client` or `windows-client.exe` by specifying a server address or domain name on the command line.  It will prompt for a password first, then attempt to authenticate with the server using that password, then report success or failure (or just hang doing nothing if the server isn't responding).

## feedback

Obviously if you can find a bug in `server.c` or even anything that could be written in a more obviously-correct manner, I'd like to hear about it.  I tried to throw every good programming practice I'm aware of at it:

- I tried to pick the least-ambiguous variable names possible.  In my opinion, ambiguous variable names are a leading cause of exploits.  Humans don't have perfect memory like a compiler does, and so if a variable's name doesn't make its purpose 100% clear, then the idea of reveiwing code becomes a joke, because the human will asssume that the variable represents whatever makes the line of code they're looking at make the most sense.

- I allocated all buffers with malloc() instead of putting them on the stack so that, should my elite coding skills fail, there's a lower chance of a buffer overflow overwriting anything useful to an exploit.

- The program compiles and runs with `-fsanitize=address`, which will immediately kill the program and report an error should it overflow any buffers.  While meant to be a temporary testing option since it slows the program, the program is fast enough to run just fine with it enabled, and, as I always say, I can buy a faster computer, but I can't buy a more secure one.  I also used some other compile-time options I'm aware of that are supposed to make programs less exploitable.

- The communications protocol uses only fixed-length buffers, hopefully again minimizing the chance of mistakes.

- I checked the man page on all of the functions to make sure I was using them and checking return values correctly.

Maybe you know more good programming practices I'm not aware of?  Note that I'm not looking for code formatting advice.  

I'm also not looking to make it more complicated.  I know it could have more features, in particular, it's one password for everyone, so "add different users with different passwords" might be the first thing someone thinks of, but features are for all of those programs this is meant to protect.  This is meant to be simple and easy for anyone to read so that, should there be a bug in it, hopefully it'll be discovered sooner rather than later.


