#! /usr/bin/ruby
 
# The preceeding line (starting with the shebang) is required to
# tell Apache where to find the Ruby interpreter for the
# following Ruby script. As far as I can tell, this has to be the
# first line in the file (even before any line breaks) otherwise it
# will throw a "Premature end of script headers" error.
 
# ------------------------------------------------------------ #
# ------------------------------------------------------------ #
 
 
# Define our collection of girls. With brackets, we can create
# implicit arrays in Ruby.
 
girls = [ "Tricia", "Sarah", "Joanna" ];
 
 
# ------------------------------------------------------------ #
# ------------------------------------------------------------ #
 
 
# Output the mime-type in the header. Notice that in Ruby, the
# puts()
puts( "Content-type: text/html" );
puts( "" );
 
# Output the page content. Notice that in Ruby, a string can
# naturally wrap multiple lines of code.
puts( "
 
	<html>
	<head>
		<title>My First Ruby Script Running On Mac</title>
	</head>
	<body>
 
		<h1>
			My First Ruby Script Running On Mac
		</h1>
 
		<p>
			Check out these stunning beauties:
		</p>
 
		<ul>
			<li>#{girls[ 0 ]}</li>
			<li>#{girls[ 1 ]}</li>
			<li>#{girls[ 2 ]}</li>
		</ul>
 
	</body>
	</html>
 
");
