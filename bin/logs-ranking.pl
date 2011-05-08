#!/usr/bin/perl

use strict;

use Net::Whois::RIS;
use Socket;
use Getopt::Std;

$| = 1;

getopt( 'f', \my %opts );

if ( !exists( $opts{'f'} ) ) {

    print "Usage of logs-ranking.pl:\n";
    print "     -f <format>\n";
    print "\n";
    print "Formats supported are:  apache\n";
    die();
}

my %iporigin;
my %ipranking;

sub BGPRankingLookup {
    my $asn = shift;
    $asn =~ s/AS//g;
    my $bgpranking =
      IO::Socket::INET->new( PeerAddr => "pdns.circl.lu", PeerPort => 43 )
      or die();
    print $bgpranking $asn . "\n";
    my $x;
    while (<$bgpranking>) {
        $x = $x . $_;
    }
    return $x;

    $bgpranking->shutdown();
}

sub getASN {
    my $ip = shift;    #or hostname

    if ( !( $ip =~ /^(\d+\.){3}\d+$/ ) ) {
        my $ipn = inet_aton($ip) or next;
        $ip = inet_ntoa($ipn);
    }

    my $l = Net::Whois::RIS->new();
    $l->getIPInfo($ip);
    return $l->getOrigin();
}

sub ipExist {
    my $ip = shift;

    if ( exists $iporigin{$ip} ) {
        return 1;
    }
    else {
        return undef;
    }

}

sub rankingExist {
    my $ip = shift;

    if ( exists $ipranking{$ip} ) {
        return 1;
    }
    else {
        return undef;
    }
}

sub ipAdd {
    my $ip  = shift;
    my $asn = shift;

    $iporigin{$ip} = $asn;
}

sub rankingAdd {
    my $ip      = shift;
    my $ranking = shift;
    $ipranking{$ip} = $ranking;

}

while (<STDIN>) {
    my $saved = $_;
    my ( @ipext, $ip );
    if ( $opts{'f'} =~ m/apache/i ) {
        @ipext = split( / /, $_, );
        $ip = $ipext[0];
    }
    else {
        die "Unsupported format\n";
    }

    if ( not ipExist($ip) ) {
        ipAdd( $ip, getASN($ip) );
    }
    if ( not rankingExist($ip) ) {
        my @rankl = split( /,/, BGPRankingLookup( $iporigin{$ip} ) );
        rankingAdd( $ip, $rankl[1] );
    }

    my @rankl = split( /,/, BGPRankingLookup( $iporigin{$ip} ) );
    print $iporigin{$ip} . "," . $ipranking{$ip} . "," . $saved;
}

