#
# DTrace.pm - DTrace output parsing and aggregating library
#
# (C) Copyright 2008 Georgios Gousios <gousiosg@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package DTrace;

use strict;
use warnings;
use base 'Exporter';

our @EXPORT =
  qw(parse parsestackdump aggregateperpackage sortkeyssortlvalues sortnvalues printhash printsortedhash
  gettopjavastackentry printjstack rundtrace gettopjavastackentry hashtoarray printcolumnaligned
  getbottomjavastackentry getprobetrigger);

=head1 NAME

DTrace - Helper functions for parsing and aggregating DTrace output

=cut

#
# Parse dtrace printa output to a hash
#
sub parse {

  my $file          = $_[0];    #File to parse
  my $start_pattern = $_[1];    #Start parsing from this
  my $end_pattern   = $_[2];    #Stop parsing whe

  my %resultlines;
  my $parse;

  open( OUT, " < $file" )
    or die "Couldn't open file $file for reading: $!\n";

  while (<OUT>) {

    next if (m/^\n/);

    if (m/$start_pattern/) {
      $parse = 1;
      next;
    }

    if (m/$end_pattern/) {
      close OUT;
      return %resultlines;
    }

    if ($parse) {

      #First group: Valid Java classnames
      #Second group: Result
      my @line = $_ =~ m/^\s*([a-zA-Z\[\/\$\;\_0-9]*)\s*(\d*)$/;

      $resultlines{ $line[0] } = $line[1];
    }
  }
  close OUT;
  die "End pattern $end_pattern not found while parsing file $file";
}

#
# Parse dtrace jstack() output
#
# Return: hash{num_parsed -> hash{stack_depth_count -> array(parsed_stack_entry) }}
#
sub parsestackdump {
  my $file          = $_[0];    #File to parse
  my $start_pattern = $_[1];    #Start parsing from this
  my $end_pattern   = $_[2];    #Stop parsing whe

  my %resultlines;
  my @line;
  my $parsed = 0;               #Stack frames parsed
  my $can_parse;                #1 if start pattern recognised
  my $stack_depth;              #Num of stack frame entries parsed
  my %lines;
  my $line_count = 0;

  open( OUT, " < $file" )
    or die "Couldn't open file $file for reading: $!\n";

  while (<OUT>) {
    $line_count++;
    next if (m/^\n/);
    next if (m/StubRoutine/);

    if (m/$start_pattern/) {
      $parsed++;
      $can_parse = 1;
      my %lines;
      next;
    }

    if ( m/$end_pattern/ && $can_parse == 1 ) {
      $can_parse            = 0;
      $stack_depth          = 0;
      $resultlines{$parsed} = {%lines};
      next;
    }

    if ($can_parse) {

      $stack_depth++;

      #Native stack frame entry
      #First group: Library shared object
      #Second group: Function
      #Third group: Offset
      if (m/`/) {
        @line = $_ =~ m/^\s*([a-zA-Z\.0-9\_]*)`(.*)\+(.*?)$/;
        $lines{$stack_depth} = [@line];
        next;
      }

      #Java stack frame entry
      #First group: Library shared object
      #Second group: Function
      if (m/\/|</) {
        @line =
          $_ =~ m/^\s*([a-zA-Z\[\/\$\;\_0-9]*)\.([<>a-zA-Z\$\[\/\_0-9]*)\(.*$/;

        #Avoid erroneous dtrace output
        if ( @line > 1 ) {
          $lines{$stack_depth} = [@line];
        }
        next;
      }

      #Not decoded frame - hex address
      if (m/^\s*0x.*/) {
        @line = $_ =~ m/^\s*(0x[0-9abcdef]*).*$/;
        $lines{$stack_depth} = [@line];
        next;
      }
      my $out = $_ =~ s/^\s*(.*)\s*$/$1/;
      print STDERR "Warn: Stack entry " 
        . $out
        . " cannot be parsed (line="
        . $line_count . ")\n";
    }
  }
  close OUT;

  if ($can_parse) {
    die "End pattern $end_pattern not found while parsing file $file\n";
  }

  return %resultlines;
}

#
#Get the top java entry in a jstack() parsed output
#
sub gettopjavastackentry {
  my (%stack) = %{ $_[0] };
  my $key, my $entry;

  #Get a numerically sorted array of keys
  foreach $key ( sort { $a <=> $b } ( keys %stack ) ) {

    #Parsed Java entries have 2 items in the array (class, method)
    if ( $#{ $stack{$key} } == 1 ) {
      return $stack{$key}[0] . "." . $stack{$key}[1];
    }
  }
}

#
#Get the bottom java entry in a jstack() parsed output
#
sub getbottomjavastackentry {
  my (%stack) = %{ $_[0] };
  my $key, my $entry;
  my $previous;

  #Get a numerically sorted array of keys
  foreach $key ( sort { $a <=> $b } ( keys %stack ) ) {
    my $length = $#{$stack{$key}} + 1;
    
    #Parsed Java entries have 2 items in the array (class, method)
    if ( $length == 2 ) {
      $entry    = $stack{$key}[0] . "." . $stack{$key}[1];
      $previous = "java";
    }
    elsif ( $previous eq "java" ) {
      return $entry;
    }
  }
}

#
#Returns the native function that triggered the DTrace probe,
#i.e. the top of the jstack() out put
#
sub getprobetrigger {
  my (%stack) = %{ $_[0] };
  
  return $stack{1}[1];
}

#
# Aggregate output per package
#
sub aggregateperpackage {

  my (%toaggr) = %{ $_[0] };
  my %aggr;

  my $key, my $value, my $package;

  while ( ( $key, $value ) = each %toaggr ) {

    $package = substr( $key, 0, rindex( $key, '/' ) );

    if ( exists $aggr{$package} ) {
      $value += $aggr{$package};
    }

    $aggr{$package} = $value;
  }

  return %aggr;

}

#
# Sort hash keys lexicographically
#
sub sortkeys {
  my (%input) = %{ $_[0] };
  return sort ( keys %input );
}

#
# Hash keys sorted by hash values values lexicographically
#
sub sortlvalues {
  my (%input) = %{ $_[0] };
  return ( sort { $input{$a} cmp $input{$b} } keys %input );
}

#
# Hash keys sorted by hash values values numerically
#
sub sortnvalues {
  my (%input) = %{ $_[0] };
  return ( sort { $input{$a} <=> $input{$b} } keys %input );
}

#
# Print aligned to the length of the largest key (+2)
#
sub printhash {
  my (%input) = %{ $_[0] };

  my $maxlength    = 0;
  my $maxvallength = 0;
  my $key, my $value, my $pad;

  foreach $key ( keys(%input) ) {
    if ( length($key) > $maxlength ) {
      $maxlength = length($key);
    }
  }

  while ( ( $key, $value ) = each(%input) ) {
    $pad = $maxlength - length($key) + length($value) + 3;
    printf( "%s%*s\n", $key, $pad, $value );
  }
}

#
# Print a hash using the specified ordered key array
#
sub printsortedhash {
  my (%input)  = %{ $_[0] };
  my (@keyset) = @$_[1];

  my $maxlength    = 0;
  my $maxvallength = 0;
  my $key, my $value, my $pad;

  foreach $key (@keyset) {
    if ( length($key) > $maxlength ) {
      $maxlength = length($key);
    }
  }

  foreach $key (@keyset) {
    $pad = $maxlength - length($key) + length($value) + 3;
    printf( "%s%*s\n", $key, $pad, $value );
  }
}

#
# Print the parsed jstack output
#
sub printjstack {
  my (%stack) = %{ $_[0] };
  my $stacknum, my $stackdepth;

  foreach $stacknum ( sort { $a <=> $b } ( keys %stack ) ) {
    print "Stack $stacknum:\n";
    foreach $stackdepth ( sort { $a <=> $b } ( keys %{ $stack{$stacknum} } ) ) {
      print "\t $stackdepth:"
        . $stack{$stacknum}{$stackdepth}[0] . " "
        . $stack{$stacknum}{$stackdepth}[1] . "\n";
    }
  }
}

#
# Prints an array of arrays aligned to column boundaries.
# Num of columns is determined from the first array length
#
sub printcolumnaligned {
  my (@array) = @{ $_[0] };
  my $columns = $#{ $array[0] } + 1;
  my @maxlengths, my $i, my $j;

  #Init the array to avoid strict environment warnigns
  for $i (0 .. $columns) {
    $maxlengths[$i] = 0;
  }

  #Get max legth per column
  for $i ( 0 .. $#array ) {
    for $j ( 0 .. $#{ $array[0] } ) {
      if ( length( $array[$i][$j] ) > $maxlengths[$j] ) {
        $maxlengths[$j] = length( $array[$i][$j] );
      }
    }
  }

  #Print aligned to max column length
  for $i ( 0 .. $#array ) {
    for $j ( 0 .. $#{ $array[0] } ) {
      my $value = $array[$i][$j];
      my $pad   = $maxlengths[$j] - length($value) + 2;
      printf( "%s%*s", $value, $pad, " " );
    }
    print "\n";
  }
}

#
# Flatten a hash to an array of arrays (1 array per key->value combination)
# key and value stings are split by spaces
#
sub hashtoarray {
  my (%input) = %{ $_[0] };
  my @result;
  my $key, my $counter;

  foreach $key ( keys %input ) {
    my @tmp1 = split( / /, $key );
    my @tmp2 = split( / /, $input{$key} );
    push( @tmp1, @tmp2 );
    $result[ $counter++ ] = [@tmp1];
  }

  return @result;
}

#Globally accessible process identifier for the dtrace process
my $pid;

#
#Run dtrace scipt defined in $1 on program with pid $2
#
sub rundtrace {

  my $dtrace = $_[0];
  my $out    = $_[1];

  if ( not defined $out ) {
    $out = "out";
  }

  #Write dtrace functions to script
  open( SOURCE, "> script.d" )
    or die "Couldn't open script.d for writing: $!\n";

  print SOURCE $dtrace;

  close SOURCE;

  #Catch Ctrl+C and forward it to dtrace
  $SIG{INT} = \&stopchild;

  #Execute dtrace script
  #$pid stores the dtrace cmd

  if ( $pid = fork ) {    # parent
    waitpid( $pid, 0 );
  }
  else {
    exec("/usr/sbin/dtrace -s script.d > $out")
      or die "can't exec dtrace: $!";
    exit;
  }

  return $out;
}

#
#Stop dtrace on Ctrl+C
#
sub stopchild {
  $SIG{INT} = \&stopchild;
  kill INT => $pid;
}

=head1 AUTHOR

Georgios Gousios <gousiosg@gmail.com>

=cut

1;
