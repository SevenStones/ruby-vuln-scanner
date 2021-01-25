#!/usr/bin/ruby


require 'versionomy'
require 'mysql'

module Osvdbcorrelator

#----first open a log file
def self.openlogfile
     begin
          logfile=File.open("/var/www/ruby/logs/cavs.log", "a+")
     rescue StandardError    
          puts "Sorry there was a file I/O problem, we're exiting"
          exit 0
     end 
     return logfile
end
#----get the scan date/time
def self.current_time
     c_time=Time.new
     c_time=c_time.strftime("%Y-%m-%d %H:%M:%S") #mySQL format
     return c_time
end

def self.engine(fuzzy_level,scan_id,wksn,product,version)

	osvdb_matches=Array.new

     if version != "" then
          case fuzzy_level
               when 1
                    #osvbd_matches=osvdb_match_lv1("apache","2.2.8")
                    osvdb_matches=osvdb_match_lv1(scan_id,product,version)
               when 2
                    osvdb_matches=osvdb_match_lv2(product,version)
               when 3
                    osvdb_matches=osvdb_match_lv3(product,version)
          end
     end
	return osvdb_matches
end 

#fuzzy level 1 checks
def self.osvdb_match_lv1(scan_id,product,version)

	db_no_error=0
	parse_no_error=0
     product_id=Array.new
     version_id=Array.new
     newer_vers=Array.new
     newer_vers_ids=Array.new
     object_correlation_ids=Array.new
	osvdb_matches=Array.new
	vuln_ids=Array.new
	reported_vulns=Array.new
	query=""

	#----call local methods to set time and logfile
	c_time=current_time
	logfile=openlogfile

	#----first open a log file
	begin
     	logfile=File.open("/var/www/ruby/logs/osvdb-correlator.log", "a")
	rescue StandardError    
     	logfile.puts("Sorry there was a file I/O problem, we're exiting")
     	exit 0
	end 
	logfile.puts("~~~~~~~~~~~~~~~~~~~~~~~~")
	logfile.puts("STARTING NEW CORRELATOR")
	logfile.puts("#{c_time}: we have been passed product #{product} and version #{version}, and we are scan id #{scan_id}")

	#----call santize method in an attempt to remove unwanted characters from product and version strings
	product,version=sanitize(product,version,scan_id)

	#----check to see if we were passed a translatable product string
	product,osvdb_TSS=translator(product)	

	#----check to see if we were passed a parsable version string
	if (version != "") 
        begin
            Versionomy.parse(version)
        rescue Versionomy::Errors::ParseError
            logfile.puts("PARSE ISSUE: Version string #{version} could not be parsed")
            reported_vulns[0]="invalid version string"
            return reported_vulns
        end
    end
	
	begin
	#connect to the MySQL server
	     dbh = Mysql.real_connect("localhost", "root", "ankSQL4r4", "osvdb")
	rescue Mysql::Error => e
	     logfile.puts("Error code: {e.errno}")
	     logfile.puts("Error message: {e.error}")
	     logfile.puts("Error SQLSTATE: {e.sqlstate}") if e.respond_to?("sqlstate")
	     dbh.disconnect if dbh
	     db_no_error=1
	end

	logfile.puts("OSVDB database connection made at #{c_time}")
    logfile.puts("after translation and sanitisation we have product parameter #{product[0]} and version #{version}")
    
     if db_no_error==0 then
        begin
            stmnt=dbh.query("SELECT id FROM object_products WHERE name LIKE '#{product}'")
            while row=stmnt.fetch_row do
                product_id<<row[0]
            end
        rescue Mysql::Error => e
            logfile.puts("Error code: {e.errno}")
            logfile.puts("Error message: {e.error}")
            logfile.puts("Error SQLSTATE: {e.sqlstate}") if e.respond_to?("sqlstate")
            dbh.disconnect if dbh
            db_no_error=1
        end
        logfile.puts("found #{product_id.size} product ids matching the nmap string")
        logfile.puts("----")

          #get all version ids from object_correlations table that match the product_id, store in array 'version_id'
          
		begin
			product_id.each do |x|		
	          	stmnt=dbh.query("SELECT object_version_id FROM object_correlations WHERE object_product_id = '#{x}'")
				while row=stmnt.fetch_row do
		               version_id<<row[0]
					end
			end
          end
          
         	logfile.puts("found #{version_id.size} version ids matching the nmap string")
		logfile.puts("----")

          #consult the object_versions table to get version strings from version ids that match the product id
          version_id.each do |v|
			parse_no_error=0
               stmnt=dbh.query("SELECT name FROM object_versions WHERE id = '#{v}'")
               #go thru each version string and compare with the passed version string from nmap, using Versionomy
               #populate newer_vars array with equal aged or newer version ids. 
               while row=stmnt.fetch_row do 
				logfile.puts("testing; #{row[0]} versus #{version}")
				product_null,ps_versi=sanitize("NULL",row[0],scan_id)    #ps_versi; post-santize version string
				begin
					Versionomy.parse(ps_versi)
				rescue Versionomy::Errors::ParseError
					logfile.puts("Version string #{row[0]} could not be parsed")
					parse_no_error=1
				end
				if parse_no_error==0 then       #if there's a parse error, skip to the next version string	
	                    if (Versionomy.parse(ps_versi) >= Versionomy.parse(version)) then
	                         newer_vers_ids<<v
	                    end                              
				end
               end
          end
         	logfile.puts("found #{newer_vers_ids.size} newer or equal versions")
		logfile.puts("----")

          
          #use the newer version ids and product ids to get object_correlations ids from object_correlation table
          product_id.each do |p|
	          newer_vers_ids.each do |x|
	               stmnt=dbh.query("SELECT id FROM object_correlations WHERE object_version_id='#{x}' AND object_product_id='#{p}'")
	               #logfile.puts "SELECT id FROM object_correlations WHERE object_version_id='#{x}' AND object_product_id='#{p}'"
	               #logfile.puts
	               while row=stmnt.fetch_row do
	                    object_correlation_ids<<row[0]
	                    end
	          end
		end
          logfile.puts("found #{object_correlation_ids.size} object correlation ids")
          
          #Getting vulnerability ids from object_links table, using the object_correlation  row id from the previous query
            object_correlation_ids.each do |x|
	          stmnt=dbh.query("SELECT vulnerability_id FROM object_links WHERE object_correlation_id='#{x}'")
                #logfile.puts "SELECT vulnerability_id FROM object_links WHERE object_correlation_id='#{x}'"
                #logfile.puts
                while row=stmnt.fetch_row do 
                    vuln_ids<<row[0]
                end
            end
        
        logfile.puts("found #{vuln_ids.size} vulnerability ids")

		#there are repeated vulnerability elements here (newer version numbers of software will have the same vulnerability up to the
		#version number where the vulnerability was fixed
		unique_vuln_ids=vuln_ids.uniq
		logfile.puts "listing unique vulnerability ids"
		unique_vuln_ids.each do |monyet|
            logfile.puts "unique vuln id: #{monyet}"
        end
            logfile.puts("found #{unique_vuln_ids.size} unique vulnerability ids")


        #in some cases there is no vulnerability table entry corresponding to the vulnerability id? 
        
		#With the vulnerability ids we can now query the vulnerability table. If there is a title search string returned by the translator method, then 
		#we search the vulnerability title field using this string...this gives us more accurate feedback	
		        
        unique_vuln_ids.each do |zz| 
        
            if (osvdb_TSS.size == 0) then
                query="SELECT osvdb_id FROM vulnerabilities WHERE id='#{zz}'"
            else
                osvdb_TSS.each do |x|
                    query="SELECT osvdb_id FROM vulnerabilities WHERE id='#{zz}' AND title LIKE '%#{x}%'"
                    stmnt=dbh.query(query)
                    logfile.puts "QUERY PASSED: #{query}"
                    while row=stmnt.fetch_row do  
                        reported_vulns<<"http://osvdb.org/show/osvdb/#{row[0]}"
                    end 
                end
            end
        end 		

	end
	dbh.close if dbh
    logfile.puts("LEAVING CORRELATOR: found #{reported_vulns.size} vulnerabilities")
	logfile.puts("~~~~~~~~~~~~~~~~~~~~~~~~")
	return reported_vulns
	

end

def self.sanitize(product,version,scan_id)


 	#----first open a log file
     begin
          logfile=File.open("/var/www/ruby/logs/sanitiser.log", "a")
     rescue StandardError    
          logfile.puts("Sorry there was a file I/O problem, we're exiting")
     end 

    logfile.puts "Entered sanitize(), for scan_id: #{scan_id}"
    logfile.puts "-------------------------------------------"
    logfile.puts 
    logfile.puts "we received product: #{product} and version: #{version}"
    logfile.puts
            
    if version.nil? then
        version=""
    end
    
     #remove spaces from the start
     p=product.sub(/^ +/,"")
     v=version.sub(/^ +/,"")
	
	if p != product then
     	logfile.puts "START-SPACES-PRODUCT: spaces shaved from start of #{product}"
	end

	if v != version then
     	logfile.puts "START-SPACES-VERSION: spaces shaved from start of #{version}"
	end

     #remove spaces from the end 
     p1=p.sub(/ +$/,"")
     v1=v.sub(/ +$/,"")

	if p1 != p then
     	logfile.puts "END-SPACES-PRODUCT: spaces shaved from end of #{p}"
	end
	if v1 != v then
     	logfile.puts "END-SPACES-VERSION: spaces shaved from start of #{v}"
	end

     # remove trailing words
     v2=v1.sub(/\s\b.+/,"")

	if v2 != v1 then
     	logfile.puts "TRAILING-WORDS-VERSION: words shaved from end of #{v1}"
	end

     #remove 'x' abominations
     if (v2 =~ /\wx$/i) then
          v3=v2.sub(/x$/,".9999999")
          logfile.puts "TRAILING-X-VERSION: 'x' replaced with nasty .9s in #{v2}"
     else
          v3=v2.gsub(/\.x/i,".9999999")
		if v3 != v2 then
          	logfile.puts "DOT-X-VERSION: '.x' replaced with nasty .9s in #{v2}"
		end
     end 


    if (v3 =~ /^all$/i) || (v3=~ /^every$/i) then
        v3="99999999.999999999"
    end



	logfile.puts
     logfile.puts "FINISHED: we returned...#{p1} and #{v3}"
	logfile.puts "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

     return p1,v3

end

def self.translator(product)

	db_no_error=0
	product_out=Array.new
	osvdb_title_search_str=Array.new
	c_time=current_time

 	#----first open a log file
     begin
          logfile=File.open("/var/www/ruby/logs/translator.log", "a")
     rescue StandardError    
          logfile.puts("Sorry there was a file I/O problem, we're exiting")
     end 

    logfile.puts "--------------------------"
    logfile.puts "OPEN TRANSLATOR: #{c_time}"
    logfile.puts
    logfile.puts
    
    
	#----setup the db connection first
	begin
	      #connect to the MySQL server
	     dbh = Mysql.real_connect("localhost", "root", "ankSQL4r4", "CAVS")
	rescue Mysql::Error => e
	     logfile.puts("Error code: #{e.errno}")
	     logfile.puts("Error message: #{e.error}")
	     logfile.puts("Error SQLSTATE: #{e.sqlstate}") if e.respond_to?("sqlstate")
	     dbh.disconnect if dbh
	     db_no_error=1
	end
	
   	if db_no_error==0 then
          begin
               stmnt=dbh.query("SELECT product_out,title_search_string FROM translation_tbl WHERE product_in LIKE '#{product}'")
               while row=stmnt.fetch_row do
                    product_out<<row[0]
                    osvdb_title_search_str<<row[1]
                    logfile.puts("TRANSLATION_MADE: input string  #{product} translated to #{row[0]}")
                    logfile.puts("OSVDB-TITLE-FIELD-SEARCH-STRING: found a search string for vulnerability title text: #{row[1]}")
                    logfile.puts
               end 
          rescue Mysql::Error => e
               logfile.puts("Error code: {e.errno}")
               logfile.puts("Error message: {e.error}")
               logfile.puts("Error SQLSTATE: {e.sqlstate}") if e.respond_to?("sqlstate")
               dbh.disconnect if dbh 
               db_no_error=1
          end 
	end
	
	dbh.close if dbh
	
	#if there was no match in the translation table for our inputted product string, then we just return as is
	logfile.puts "THERE ARE #{product_out.size} elements in the products_out array"
	
	if product_out.size==0 then
        
        logfile.puts "We received product string input: #{product}, and output product string: #{product} and osvdb_TSS: #{osvdb_title_search_str[0]}"
        logfile.puts 
        logfile.puts "EXIT TRANSLATOR: #{c_time}"
        logfile.puts "--------------------------"
        return product,osvdb_title_search_str
        
	else 
	
        product_out_uniq=product_out.uniq
        osvdb_title_search_str_uniq=osvdb_title_search_str.uniq
        osvdb_title_search_str_uniq.each do |x|
            logfile.puts "We received product string input: #{product}, and output product string: #{product_out_uniq[0]} and osvdb_TSS: #{x}"
        end
        logfile.puts "--------------------------"
        logfile.puts "EXIT TRANSLATOR: #{c_time}"
    
        return product_out_uniq,osvdb_title_search_str_uniq
	end
end


def osvdb_match_lv2(product,version,dbh)
     return results
end

def osvdb_match_lv3(product,version,dbh)
     return results
end

def ian_vdb_match
end

end
