#!/usr/bin/env ruby
require "cgi"
cgi = CGI.new("html4")
cgi.out{
  cgi.html{
    cgi.head{ "\n"+cgi.title{"Ruby is working!"} } +
    cgi.body{ "\n"+
      cgi.h1 { "Ruby is working!" } + "\n"+
      cgi.p { "Now it's time to get on with some real work." }
    }
  }
}