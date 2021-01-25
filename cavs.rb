#!/usr/bin/ruby


scan_id=0
host_up=0
port_status_msg=""
ip_address=""
wellknownsrvname=""
productname=""
versi=""
product_str=""
message=""

require 'nmap/parser'
require 'cgi'
require 'mysql'
require 'osvdbcorrelationengine'
require 'nokogiri'
require 'net/smtp'

results = Array.new
arr = Array.new
osvdb_url_array = Array.new

#----get the scan date/time
def current_time

     c_time=Time.new
     c_time=c_time.strftime("%Y-%m-%d %H:%M:%S") #mySQL format
     return c_time
end
c_time=current_time


#----first open a log file
def openlogfile

	begin		
	logfile=File.open("/var/www/ruby/logs/cavs.log", "a+")
	rescue StandardError	
		puts "Sorry there was a file I/O problem, we're exiting"
		display_footer(logfile)
	end 
	return logfile
end
logfile=openlogfile


def display_footer(logfile)

     c_time=current_time
     logfile.puts("#{c_time}: script ended","=================","")
     
     f = File.new("/var/www/7-stones/htdocs/scripts/ruby/template-foot.txt")
     begin
          while (line = f.readline)
               line.chomp
               puts line
          end
     rescue EOFError
          f.close
     end
     exit 0
end

def validate_ip (ip_address)
  
     valid=false
     ipPattern = /^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$/;

     if (ip_address =~ ipPattern) then valid=true
     end

     if (ip_address != "0.0.0.0") then valid=true
     else return false
     end
          
     if (ip_address != "255.255.255.255") then valid=true
     else return false
     end
     
     if (ip_address != "127.0.0.1") then valid=true
     else return false
     end
     
     if valid==true then return true
     else return false
     end
     
end
  
puts( "Content-type: text/html" );
puts( "" );

File.open("/var/www/7-stones/htdocs/scripts/ruby/template-head.txt").each { |line|
    puts line
}


#----setup the db connection first
begin
      #connect to the MySQL server
     dbh = Mysql.real_connect("localhost", "root", "ankSQL4r4", "CAVS")
rescue Mysql::Error => e
     logfile.puts("Error code: #{e.errno}")
     logfile.puts("Error message: #{e.error}")
     logfile.puts("Error SQLSTATE: #{e.sqlstate}") if e.respond_to?("sqlstate")
     dbh.close if dbh
     puts "Sorry, there was a database connectivity problem, we're exiting"
     display_footer(logfile)
end

logfile.puts("#{c_time}: opened CAVS dbase connection") 

#-----method declaration
def db_data_insert(f1,f2,f3,f4,f5,f6,f7)

     begin
          stmnt=f6.prepare("INSERT INTO scan_data (scan_id,srv_name,port_num,srv_product,srv_version) VALUES (?,?,?,?,?)")
          stmnt.execute(f1,f2,f3,f4,f5)
          port_id=f6.insert_id
          return port_id
     rescue Mysql::Error => e
          f7.puts("Error code: #{e.errno}")
          f7.puts("Error message: #{e.error}")
          f7.puts("Error SQLSTATE: #{e.sqlstate}")
          puts "Sorry, there was a database connectivity problem, we're exiting"
     	display_footer(logfile)
     end
end

def osvdb_data_update(port_id,wksn,port,product,versi,osvdb_url,dbh,logfile)
	
	begin
		stmnt=dbh.prepare("INSERT INTO scan_vulns (port_id,service_name,port_number,product,version,osvdb_url) VALUES (?,?,?,?,?,?)")
		stmnt.execute(port_id,wksn,port,product,versi,osvdb_url)
	rescue Mysql::Error => e
          logfile.puts("Error code: #{e.errno}")
          logfile.puts("Error message: #{e.error}")
          logfile.puts("Error SQLSTATE: #{e.sqlstate}")
          dbh.close if dbh
          puts "Sorry, there was a database connectivity problem, we're exiting"
     	display_footer(logfile)
     end

end

def send_email(from, from_alias, to, to_alias, subject, message)
	msg = <<END_OF_MESSAGE
From: #{from_alias} <#{from}>
To: #{to_alias} <#{to}>
Subject: #{subject}
	
#{message}
END_OF_MESSAGE
	
	Net::SMTP.start('localhost') do |smtp|
		smtp.send_message msg, from, to
	end
end

def display_port_results(osvdb_msg,port,wksn,product,versi,osvdb_url,logfile)

     puts "<div id=\"cavs-ro\">"
	puts "<h4>Port: #{port}</h4>"
	
	logfile.puts "---------------"
	logfile.puts "In display_port_results()"
	logfile.puts 
	logfile.puts "we received osvdb_msg: #{osvdb_msg}"
	logfile.puts "we received port: #{port}"
	logfile.puts "we received wksn: #{wksn}"
	logfile.puts "we received product: #{product}"
	logfile.puts "we received versi: #{versi}"
	logfile.puts "----------------"
	
	
	if versi.nil? then
	    logfile.puts "versi is empty"
	    versi="no version information found"
     end
	
	if product.nil? then
	    logfile.puts "product is empty"
	    product="no product information found"
     end


     puts "<p>Service (from /etc/services): #{wksn}</p>"
     puts "<p>Product String: #{product}</p>"
     puts "<p>Version String: #{versi}</p>"


	puts "<h4>Vulnerability Results</h4>"
	
	
	#unless the version string could not be parsed, or there were no vulnerability issues reported
	#then print the results
	
	if osvdb_msg.nil? then
		
		puts "<p>See the following link(s) for an explanation of the issue(s) found:</p>"
				
		osvdb_url.each do |x|
			puts "<a href=\"#{x}\">#{x}</a><br />"
			end
	else
		puts "<span class=\"green\">#{osvdb_msg}</span>"
	end
	puts "</div>"
end



#-----main body of code

cgi = CGI.new
ip_address = cgi['IPvalue'];
clients_ip = cgi['Client_IPvalue'];
#fuzzy_level=cgi['fuzzy_level'];
fuzzy_level=1


d_ip=dbh.escape_string(ip_address)
if validate_ip(d_ip)==false 
     puts "<p>";
     puts "The IP address submitted is invalid";
     puts "</p>";
     display_footer(logfile)
end

s_ip=dbh.escape_string(clients_ip)
if (s_ip !="127.0.0.1" ) then
     if validate_ip(s_ip)==false then
          puts "<p>";
          puts "The IP address submitted is invalid";
          puts "</p>";
          display_footer(logfile)
     end
end

#informational alert mail, just to alert me that a scan is happening somewhere
message="CAVS scan just kicked off, #{s_ip} is scanning #{d_ip}"
send_email("CAVS-admin@seven-stones.co.uk","CAVS Admin","ian.tibble@seven-stones.co.uk","Ian Tibble","CAVS scan initiated",message)

p = Nmap::Parser.parsescan("nmap", "-sV #{ip_address}")

#output the next block of HTML
puts("<p class=\"h3\">Target IP address: #{ip_address}</p>");
puts("<p>Runtime: #{p.session.scan_time} seconds</p>");
puts("</div>");
puts("<p>&nbsp;</p>");
puts("<div id=\"cavsresults\">");

#insert scan parameters

begin
	stmnt=dbh.prepare("INSERT INTO scan_param (s_ip,d_ip,scan_date) VALUES (?, ?, ?)")
	stmnt.execute(s_ip,d_ip,c_time)
	scan_id=dbh.insert_id
rescue Mysql::Error => e
	logfile.puts("Error code: #{e.errno}")
	logfile.puts("Error message: #{e.error}")
	logfile.puts("Error SQLSTATE: #{e.sqlstate}") if e.respond_to?("sqlstate")
	dbh.close if dbh
	puts "Sorry, there was a database connectivity problem, we're exiting"
	display_footer(logfile)
end


cock = p.session.numhosts("up")


if p.hosts("up").size == 0 then
     host_up=1
     puts "<p>";
     puts "Sorry your specified target host is down or non-existant or we timed out in our connection attempt";
     puts "</p>";
     display_footer(logfile)
end

productStr = String.new("")

if host_up then
     p.hosts("up") do |host|
          [:tcp].each do |type|
               host.getports(type, "open") do |port|
                    srv = port.service
                    
      			port_id=db_data_insert(scan_id, srv.name, port.num, srv.product, srv.version, dbh, logfile)
                    
                    logfile.puts "srv.name is #{srv.name}"
                    logfile.puts "srv.product is #{srv.product}"
                    logfile.puts "srv.version is #{srv.version}"
                    logfile.puts
                    
                    #if we're ok this point, we can go ahead and call our OSVDB correlation engine
                    
                    unless srv.product.nil? then
                         logfile.puts "#{srv.product} srv.product is not nil"
                         logfile.puts "calling osvdb correlator"
                         results = Osvdbcorrelator::engine(fuzzy_level,scan_id,srv.name,srv.product,srv.version)
                         results.each do |zz|
                              logfile.puts "Back from correlator, we received for product string #{srv.product}: #{zz}"
                         end
                    else
                         logfile.puts "#{srv.product} srv.product is nil"
                    end
                                             
                    if results[0]=="invalid version string" then
                         logfile.puts("we were unable to parse the nmap version string #{versi}")
                         osvdb_url_array="NULL"
                         osvdb_msg="version string parse failed"
                    end
                    
                    if results.size == 0 then
                         logfile.puts "product #{srv.product}: results is nil"
                         osvdb_msg="No issues found"
                    else 
                         logfile.puts "product #{srv.product}: results is not nil"
                         #handling both dbase storage and display of results
                         results.each do |osvdb_url|
                              osvdb_data_update(port_id,srv.name,port.num,srv.product,srv.version,osvdb_url,dbh,logfile)
                         end
                    end	
             
                    #pass the array of OSVDB results if there are any
                    display_port_results(osvdb_msg,port.num,srv.name,srv.product,srv.version,results,logfile)
                    osvdb_msg=""
               end
          end
     end
end

display_footer(logfile)
logfile.close