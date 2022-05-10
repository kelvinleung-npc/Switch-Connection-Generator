
use strict; 
use warnings; 
use Data::Dumper qw(Dumper);

# | -- DISCOVERY  -- |
# Abstract: 
# The program DISCOVERY accomplishes 4 tasks: 
# 1) creates direct port connections between switches (LLDP) and the root router (router connections have "unknown" as port linkage instead of ex. "ge-0/0/2.0" as mac info only on switch side)
# 2) identifies port connections that have named location discrepancies ex ______ mismatching connection with _____
# 3) identifies ports with an unusually high amount of end point traffic (used to flag potential unauthorized switches on the network) prints out macs of cisco devices as well
# 4) finds files without a known root router aka ungrouped files (usually switches without table data)
#
# Output is in CSV format: 
# EX: 
# 1) _______,ge-0/0/2.0,_______,port connection
# 2) _______,ge-0/0/10.0,_______,port connection location names don't match
# 3) _______,Gi1/1/2, excessive,4 macs observed- possible Cisco Devices: Cisco Systems 84:b8:02:41:df:b1
# 4) ungrouped files,,_______..., ungrouped files
#
# 
# Structure of Files:
# These files contain Interface and ARP tables: 
#

# Interface             [              MAC] :    Admin     Oper  Addresses
# GigabitEthernet0      [34:6f:90:39:ac:9c] :  down(2)  down(2)  
# GigabitEthernet0/1    [34:6f:90:39:ac:81] :  down(2)  down(2)  
# ...
# Vlan11                [34:6f:90:39:ac:c0] :    up(1)    up(1)  10.112.12.241 10.112.48.33
# Vlan610               [34:6f:90:39:ac:c0] :    up(1)  down(2)  10.176.52.1
# Vlan617               [34:6f:90:39:ac:c0] :    up(1)    up(1)  10.183.3.1
#
# ARP:
# 10.183.3.2      : 00:03:4F:0D:17:2C
# 10.112.12.244   : 00:3A:7D:05:F9:D4 : abbss016.net.gov.bc.ca
# 10.112.12.242   : 2C:3E:CF:6D:E8:C1 : abbsm001.net.gov.bc.ca
# 142.26.188.129  : 34:6F:90:39:AC:C0 : abbrv129.lan.net.gov.bc.ca
# 10.176.52.1     : 34:6F:90:39:AC:C0
# ...
# 
# And exclusively in switch files they also contain MAC Tables and Linked Layer Discovery Protocol Tables (LLDP)
# (LLDP is ignored because it is not used in the program)
# MAC Table:
# Trying 10.112.15.106...
#           Mac Address Table
# -------------------------------------------

# Vlan    Mac Address       Type        Ports
# ----    -----------       --------    -----
#    5    0007.4d53.1a57    DYNAMIC     Gi1/1
#    5    0007.4d54.6d12    DYNAMIC     Gi1/1
#    5    2c0b.e99c.5640    DYNAMIC     Gi1/1
#    5    482a.e357.09c3    DYNAMIC     Gi1/1
# ...
# 
# Logic of Program: 
# Read in all files and get a hash called $mac_switchrouter_hash that identifies what switch it is based on the mac address.
# Read all files again creating a hash called $switch_port_mac_hash that contains the mac addresses for each switch on each of its ports.
# Process the $switch_port_mac_hash data to get hashes of %only_routers and %only_switches which only contain router macs or only switch macs respectively.
# Remove their duplicates and create a count of how many times a router is seen in a switch (%router_count).
# group the switches by the highest count router that appears in their mac tables. This creates a pseudospanning tree which speeds up processing time. 
# Build the switch connections by going by groupings and using switch connections. order from smallest sized mac table to largest. make a loop and remove macs found in smallest from all 
# other switches leaving each table with mac connections. 
# Do same process but this time take $switch_port_mac_hash and remove switches and routers from it first. then it is left with macs at their destination only. 
# Now we can check for suspiciously large ports to flag.  
# create an OUI table look up to convert mac addresses into device types + macs can be used to identify cisco devices on ports 

sub remove_duplicates_from_array (@){ 
    my %seen; 
    my @non_dupe = grep { not $seen{$_}++ } @_; 
}
#removes duplicates from the ports 
sub non_duplicate_hash {
    my $hash = shift; 
    my %hash = %{$hash};
    my %return_hash; 
    for my $switch (keys %hash){
        for my $port (keys %{$hash{$switch}}){
            my @array = @{$hash{$switch}{$port}};
            my @non_duplicate = remove_duplicates_from_array(@array); 
            $return_hash{$switch}{$port} = \@non_duplicate; 
        }
    }
    return %return_hash; 
}
#determine the root router of a switch based on how many switches
#have that that router in its mac table. the root router of a switch 
#is the router with the largest count as the root of the spanning tree
#is found in every mac table. 
#use the count hash on each switch after to sort
sub create_router_count {
    my $only_routers = shift; 
    my %only_routers = %{$only_routers}; 
    my %router_count;
    for my $switch (keys %only_routers){
        my %seen;
        for my $port (keys %{$only_routers{$switch}}){
            my @array = @{$only_routers{$switch}{$port}};
            for my $element (@array){
                $seen{$element} = 'exist'; 
            }
        }
        for my $seen (keys %seen){
            $router_count{$seen}++;
        }
    }
    return %router_count; 
}

#create a check to see if switch1 and switch 2 contain each other
#they shouldnt contain each other because of spanning tree 
#if they contain each other there is a loop somewhere
#just makes pairs of {switch1}{switch2} so it can be processed for loops
sub create_switch_looping_lookup {
    my $only_switches = shift; 
    my %only_switches = %{$only_switches};
    my %switch_looping_check; 
    for my $switch1 (keys %only_switches){
        for my $port (keys %{$only_switches{$switch1}}){
            my @array = @{$only_switches{$switch1}{$port}};
            for my $switch2 (@array){
                $switch_looping_check{$switch1}{$switch2} = 'exists';
            }
        }
    }
    return %switch_looping_check; 
}
# groups switches into their root router grouping for speeding up processing
# finds switches without a known router
sub group_files {
    my $only_routers = shift; 
    my %only_routers = %{$only_routers};
    my $router_count = shift; 
    my %router_count = %{$router_count};
    my %grouped_files; 
    my @ungrouped_files; 

    for my $switch (keys %only_routers){
        my $largest_count = 0; 
        my $largest_seen = 'none'; 
        for my $port (keys %{$only_routers{$switch}}){
            my @array = @{$only_routers{$switch}{$port}}; 
            for my $element (@array){
                if(!exists($router_count{$element})){
                    next; 
                }
                elsif($router_count{$element} > $largest_count){
                    $largest_seen = $element; 
                    $largest_count = $router_count{$element};
                }
                elsif($router_count{$element} == $largest_count){
                    if ($element lt $largest_seen){
                        $largest_seen = $element; 
                    }
                }
            }
        }

        #catch the files with no mac table or just have a different mac table structure
        if($largest_seen eq 'none'){
            push(@ungrouped_files,$switch);
        }
        elsif(exists($grouped_files{$largest_seen})){
            my @array = @{$grouped_files{$largest_seen}}; 
            push(@array, $switch);
            $grouped_files{$largest_seen} = [@array]; 
        }

        else {
            $grouped_files{$largest_seen} = [$switch];
        }
    }
    return (\%grouped_files, \@ungrouped_files);
}

#used to grab the size of the mac table in the switch
#this is used to order the switches in the cluster so
#they can be processed from access(leaf) switches
#to the root. 
sub get_hash_of_switch_sizes {
    my $cluster = shift; 
    my @cluster = @{$cluster};
    my $switch_port_mac_hash = shift; 
    my %switch_port_mac_hash = %{$switch_port_mac_hash};
    my %switch_size_hash;
    for my $switch (@cluster){
        $switch_size_hash{$switch} = 0;
        for my $port (keys %{ $switch_port_mac_hash{$switch}}){
            next if(($port eq 'notexist')); 
            my @array = @{$switch_port_mac_hash{$switch}{$port}};
            my $port_size = scalar(@array);
            $switch_size_hash{$switch} = $switch_size_hash{$switch} + $port_size;    
        }
    }
    return %switch_size_hash; 
}

#looks at the switch's port and returns the size of the port. 
sub switch_port_size {
    my %switch_to_grab_sizes = %{$_[0]}; 
    my $switch = $_[1]; 
    my %outer_switch_port_size_hash; 
    for my $port (keys %{ $switch_to_grab_sizes{$switch}}){
        my @array = @{$switch_to_grab_sizes{$switch}{$port}};
        my $port_size = scalar(@array);
        $outer_switch_port_size_hash{$port} = $port_size;
    }
    my @sortedport; 
    for my $port ( sort { $outer_switch_port_size_hash{$a} <=> $outer_switch_port_size_hash{$b} } keys %outer_switch_port_size_hash ){
        push( @sortedport,$port ); 
    }
    return \@sortedport; 
}

#build connections processing the data in only_switches 
#and outputting switch connections the parent switches 
#have to the child
sub build_downstream_switch_connections {
    my %grouped_files = %{$_[0]};
    my %only_switches = %{$_[1]};
    my %switch_port_mac_hash = %{$_[2]};
    my %switch_connections; 
    my %deleted_from;
    for my $cluster  (keys %grouped_files){
        my @cluster = @{$grouped_files{$cluster}};
        my %switch_size_hash = get_hash_of_switch_sizes(\@cluster,\%switch_port_mac_hash);
        my @ordered_by_smallest_mac_table; 
        foreach my $switch (sort {$switch_size_hash{$a} <=> $switch_size_hash{$b}} keys %switch_size_hash){
            next if ($switch_size_hash{$switch} == 0);
            push(@ordered_by_smallest_mac_table, $switch); 
        }
        for my $switch (@ordered_by_smallest_mac_table){
            $switch_connections{$switch} = []; 
        }
        for my $switch (@ordered_by_smallest_mac_table){
            my $loop = 0 ; 
            my $deletion_flag = 0; 
            for my $port (keys %{$only_switches{$switch}}){
                my @port_macs = @{$only_switches{$switch}{$port}};
                my %switch_macs_in_port;
                for my $macs (@port_macs){
                    $switch_macs_in_port{$macs} = 'exists';
                }
                if (scalar(@port_macs) == 1){
                    my @connection_list = @{$switch_connections{$switch}};
                    push (@connection_list, [$port,$port_macs[0]]);
                    $switch_connections{$switch} = [@connection_list];

                }
                for my $innerswitch (@cluster){
                    next if ($switch eq $innerswitch); 
                    for my $inner_port (keys %{$only_switches{$innerswitch}}){
                        next if ($inner_port eq "notexist");
                        my @mac_array = @{$only_switches{$innerswitch}{$inner_port}};
                        my @updated_mac_array; 
                        for my $element (@mac_array){
                            if (exists($switch_macs_in_port{$element})){
                                $deletion_flag = 1;  
                                $deleted_from{$innerswitch} = 'exists';
                            }
                            else{
                                push(@updated_mac_array, $element); 
                            }
                        }
                        $only_switches{$innerswitch}{$inner_port} = [@updated_mac_array];
                    }
                }
                delete($only_switches{$switch}{$port}); 
            }
            if($deletion_flag == 0 && exists($deleted_from{$switch})){
                my @connection_list = @{$switch_connections{$switch}};
                push (@connection_list, ["unknown",$cluster]);
                $switch_connections{$switch} = [@connection_list];
            }
        }
    }
    return \%switch_connections; 
}

#order the cluster of files by smallest switch to largest switch 
#by deleting elements from smallest to largest in the spanning tree we can 
#reduce the ports on each switch down to the final destination of the mac address
#i.e the destination port 
#this also eliminates the root router and known switches as their destination
#is irrelevant at this point. we are looking for unknown switches 

sub order_by_size {
    my %switch_size_hash = %{$_[0]};
    my @ordered_by_smallest_mac_table;
    foreach my $switch (sort {$switch_size_hash{$a} <=> $switch_size_hash{$b}} keys %switch_size_hash){
        next if ($switch_size_hash{$switch} == 0);
        push(@ordered_by_smallest_mac_table, $switch); 
    }
    return @ordered_by_smallest_mac_table; 
}

#This program reads in device files in order to do two things:
#1) build the linked layer discovery protocol of switches (switch direct connections)
#2) determine if there is an unauthorized or unknown switch or access point going out 
# of a switch's port. 

#location of all the device files 
my $dirname = '____________';
opendir(DIR, $dirname) or die "Could not open $dirname\n";
my @location_files;

#grab all file names 
while (my $filename = readdir(DIR)) {
    if($filename =~//){
    push(@location_files, $filename); 
    }    
}


my %switch_port_mac_hash;  #{switch}{port} = [list of mac addresses]
my %mac_switchrouter_hash; #{mac} = name of device (vdhss001)



#grab all the mac addresses of routers and switches from all over BC
# reads in the files located in /var/NNR/data/ifstat/ and returns 
# a hash table of the mac address of the devices. The router's mac address
# is unknown, so all mac addresses on its interface table is read in. 

my @file_list = @location_files;
for my $i (@file_list){
    if ($i =~ /^...[rg][a-z]\d{3}/){
        open(FH,'<', $dirname.'/'."$i") or die "could not open file";
        while(<FH>){
            #grab all mac addresses f
            if($_ =~ /\[\s*([a-zA-Z0-9:]+)\]/){
                if(($1 ne "MAC") && ($1 ne "0:0:0:0:0:0") ){
                    my @macarray = split(':',$1);
                    for my $hex (@macarray){
                        if (length($hex) < 2){
                            $hex = "0".$hex; 
                        }
                    }
                    my $mac = join(':',@macarray);
                    $mac_switchrouter_hash{$mac} = $i; 
                }
            }
        }
    }
    if ($i =~ /^...[s][a-z]\d{3}/){
        open(FH,'<', $dirname.'/'."$i") or die "could not open file";
        while(<FH>){
            if($_ =~ /^(Vlan11|irb.11)\s*\[\s*([a-zA-Z0-9:]+)\]/){
                if(($1 ne "MAC") && ($1 ne "0:0:0:0:0:0") ){
                    my @macarray = split(':',$2);
                    for my $hex (@macarray){
                        if (length($hex) < 2){
                            $hex = "0".$hex; 
                        }
                    }
                    my $mac = join(':',@macarray);
                    $mac_switchrouter_hash{$mac} = $i; 
                }
            }
        }
    }
}

#process the device's mac table for all macs it contains and organize them
# by port. below is some of the formatting that device mac tables can take 
#the form of for processing. 
for my $i (@file_list){
    #skip grabbing routers
    if ($i =~ /^...[rg]/){
        next; 
    }
    my $state = 0; 
    open(FH,'<', $dirname.'/'."$i") or die "could not open file";
    while(<FH>){
        ######## text processing phase ########
        ###only process the mac table###
        ###Put Mac Tables into hashes of {switch}{port} = {mac}
        if($_ =~ /^[0-9\s]{4}\s+([a-zA-Z0-9.]+)\s+DYNAMIC\s+(\S+)/ || $_ =~/^[0-9\s]{4}\s+([a-zA-Z0-9.]+)\s+dynamic\s\S+\s+(\S+)/){ 
            my $mac = $1; 
            my @mac = split('\.',$mac); 
            $mac = '';
            for my $hex (@mac){
                my $sub1 = substr($hex,0,2); 
                my $sub2 = substr($hex,2,2); 
                $mac = $mac.":".$sub1.":".$sub2; 
            }
            if (length($mac) > 0){
                $mac = substr($mac,1);
            }
            ### create a list of macs per port in switch 
            if (exists ($switch_port_mac_hash{$i})){
                if (exists($switch_port_mac_hash{$i}{$2})){
                    my @array = @{$switch_port_mac_hash{$i}{$2}};
                    push(@array, $mac);
                    $switch_port_mac_hash{$i}{$2} = \@array; 
                }
                else {
                    $switch_port_mac_hash{$i}{$2} = [$mac];
                }
            }
            else {
                    $switch_port_mac_hash{$i}{$2} = [$mac];  
            }
        } 
        elsif ( $_ =~ /([a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2})\s+D\s+\-\s+([a-zA-Z\-\/\.0-9]+)/ ){
            my $mac = $1; 
            ### create a list of macs per port in switch 
            if (exists ($switch_port_mac_hash{$i})){
                if (exists($switch_port_mac_hash{$i}{$2})){
                    my @array = @{$switch_port_mac_hash{$i}{$2}};
                    push(@array, $mac);
                    $switch_port_mac_hash{$i}{$2} = \@array; 
                }
                else {
                    $switch_port_mac_hash{$i}{$2} = [$mac];
                }
            }
            else {
                    $switch_port_mac_hash{$i}{$2} = [$mac];  
            }
        }

    }
    if (exists ($switch_port_mac_hash{$i}) == 0){
        $switch_port_mac_hash{$i}{'notexist'} = [];
    }
}

###-- MAIN LOGIC OF CODE --###
# take the complete mactable hash and cut out all the non necessary processing data 
# for building the switches creating two minimalist hashes. makes the process of determining
# what is the switch's root router for grouping and building the switch connections much easier
# by only keeping known device data we can build switch connections

my %only_routers;
my %only_switches; 
for my $switch (keys %switch_port_mac_hash){
    for my $port (keys %{$switch_port_mac_hash{$switch}}){
        my @maclist = @{$switch_port_mac_hash{$switch}{$port}};
        my @router_list; 
        my @switch_list; 
        for my $mac (@maclist){
            if(exists($mac_switchrouter_hash{$mac})){
                if($mac_switchrouter_hash{$mac} =~ /^...[rg]/){
                    push(@router_list,$mac_switchrouter_hash{$mac});
                }
                if($mac_switchrouter_hash{$mac} =~ /^...s/){
                    push(@switch_list,$mac_switchrouter_hash{$mac});
                }
            }
        } 
        $only_routers{$switch}{$port} = \@router_list;
        $only_switches{$switch}{$port} = \@switch_list;
    }
}

#main idea of finding root router: 
#group the switches by largest counted router they have in their mactable
#will also speed up the switch connections because it can scan only lines 
#in own spanning tree (which is unknown) rather than all files
#largest router is the root of grouping

%only_routers = non_duplicate_hash(\%only_routers);
%only_switches = non_duplicate_hash(\%only_switches);
my %router_count = create_router_count(\%only_routers); 
my ($grouped_files,$ungrouped_files) = group_files(\%only_routers,\%router_count); 
my %grouped_files = %{$grouped_files};
my @ungrouped_files = @{$ungrouped_files};
my @grouped_files = keys %grouped_files; 

# build the switch connections
# connections only exist from upstream switches to downstream
# in the mac table 
my %switch_connections = %{build_downstream_switch_connections(\%grouped_files,\%only_switches,\%switch_port_mac_hash)}; 
for my $group (keys %grouped_files){
    my @group = @{$grouped_files{$group}};
    for my $switch (@group){
        my @array = @{$switch_connections{$switch}};
        if (scalar(@array) == 0){
            my $flag = 0;
            for my $switch1 (keys %switch_connections){
                my @switcharray = @{$switch_connections{$switch1}};
                for my $element (@switcharray){
                    if($element->[1] eq $switch){
                        $flag = 1; 
                    }
                }
            }
            if($flag == 0){
                push(@array, ['unknown',$group]);
                $switch_connections{$switch} = [@array];
            }
        }
    }
}
# # clusters are the root router of the device spanning trees
# # used for grouping switches to be processed. 
# # eliminate all known router and switch information leaving only 
# # unknown device information to be processed for flagging 
# # of suspiciously large port sizes.
# # also delete macs that are not at their destination port (furthest down spanning tree)
# # therefore organize switches in cluster by smallest mactable size
# # and delete all instances of mac addresses that are found in the smallest
# # switch from all other switches. this works because of the spanning tree 
# # relationship. parent switches will contain all child mac addresses plus their own connections
%switch_port_mac_hash = non_duplicate_hash(\%switch_port_mac_hash);
for my $cluster  (keys %grouped_files){
    my @cluster = @{$grouped_files{$cluster}};
    my %cluster_macs;
    my %switch_size_hash = get_hash_of_switch_sizes(\@cluster,\%switch_port_mac_hash);
    my @ordered_by_smallest_mac_table = order_by_size(\%switch_size_hash);
    my %processed_switch; 
    for my $switch (@ordered_by_smallest_mac_table){
        my $loop = 0 ; 
        for my $port (keys %{$switch_port_mac_hash{$switch}}){
            my @port_macs = @{$switch_port_mac_hash{$switch}{$port}};
            my @updated_port; 
            for my $element (@port_macs){
                if (exists($mac_switchrouter_hash{$element})){
                    next; 
                }
                else{
                    push(@updated_port,$element);
                }
            }
            $switch_port_mac_hash{$switch}{$port} = [@updated_port]; 
            my %switch_macs_in_port;
            for my $macs (@port_macs){
                $switch_macs_in_port{$macs} = 'exists';
            }
            for my $innerswitch (@cluster){
                next if ($switch eq $innerswitch); 
                next if (exists($processed_switch{$innerswitch}));
                for my $inner_port (keys %{$switch_port_mac_hash{$innerswitch}}){
                    next if ($inner_port eq "notexist");
                    my @mac_array = @{$switch_port_mac_hash{$innerswitch}{$inner_port}};
                    my @updated_mac_array; 
                    for my $element (@mac_array){
                        if (exists($switch_macs_in_port{$element})){
                            next; 
                        }
                        else{
                            push(@updated_mac_array, $element); 
                        }
                    }
                    $switch_port_mac_hash{$innerswitch}{$inner_port} = [@updated_mac_array];
                }
            }
        }   
    $processed_switch{$switch} = 'exists';
    }
}

# #read in organizational unit identifier directory to see if mac address is a cisco product
my $ouidirectory = '_______';
my $ouifile = "oui.txt";
my %ouihash; 
open(FH,'<', $ouidirectory.'/'.$ouifile) or die "could not open file";
while(<FH>){
    if ($_ =~ /^([a-zA-Z0-9]{2}-[a-zA-Z0-9]{2}-[a-zA-Z0-9]{2})\s+\(hex\)\s*(.*)/){
        my $macprefix = $1; 
        my $companyname = $2; 
        $macprefix = lc($macprefix); 
        $macprefix =~ s/-/:/; 
        $macprefix =~ s/-/:/;  
        $ouihash{$macprefix} = $companyname;
    }
}

# # create a [oui, mac] pairing switch port hash from switch port mac hash
# # used to do checks to see if large port output contains a cisco product. 
my %find_unknown_switches = %switch_port_mac_hash;
my %oui_switch_port_mac_hash; 
for my $switch (keys %find_unknown_switches){
    for my $port (keys %{$find_unknown_switches{$switch}}){
        my @array = @{$find_unknown_switches{$switch}{$port}}; 
        my @new_array; 
        for my $mac (@array){
            if ($mac =~ /^([\S]{8})/){
                my $name = $ouihash{$1}; 
                if(defined($name)){
                    push(@new_array, [$name,$mac]);
                }
                else {
                    push(@new_array,['unknown device',$mac]);
                } 
            }
        }
    $oui_switch_port_mac_hash{$switch}{$port} = [@new_array];
    }
}

# # final chunk of the analysis
# # look over the oui_switch_port_mac_hash and output in a csv file
# # ports that are suspiciously large and if they contain cisco devices 
# # also output switch connections and if those connections are connected to 
# # incorrectly named location devices. ie (vdh and gol connected)
for my $switch (keys %oui_switch_port_mac_hash){ 
    for my $port (keys %{$oui_switch_port_mac_hash{$switch}}){
        my @array = @{$oui_switch_port_mac_hash{$switch}{$port}}; 
        my $count = 0; 
        my @cisco_devices; 
        for my $element (@array){
            $count++; 
            if($element->[0] =~ /Cisco Systems/){
                push(@cisco_devices, "Cisco Systems ".$element->[1]);
            }
        }
        if($count >3){
            if(scalar(@cisco_devices) > 0){
                my @array; 
                for my $element (@cisco_devices){
                    push(@array, $element);
                }
                print "$switch,$port, excessive,$count macs observed- possible Cisco Devices: @array\n";
            }
            else{
                print "$switch,$port,excessive,$count macs observed'\n";
            } 
        }  
    }
    if(defined($switch_connections{$switch})){
        if($switch =~ /^([\S]{3})/){
            my $location = $1; 
            my @connections = @{$switch_connections{$switch}}; 
            for my $pair (@connections){
                my @pair = @{$pair};
                if($pair[1] =~ /^$location/){
                    print "$switch,$pair[0],$pair[1],port connection\n";
                }
                else{
                    print "$switch,$pair[0],$pair[1],port connection location names don't match\n";
                }
            }
        }
    }
}
if (scalar(@ungrouped_files)){
    print "ungrouped files,,@ungrouped_files, ungrouped files\n"; 
}
