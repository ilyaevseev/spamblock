#!/usr/bin/perl
#
#  == spamblock ==
#  Detect and block spammers/attackers on FreeBSD- and Linux-based routers/servers.
#
#  Written at Jun 2009, Apr 2010, Sep-2021 by ilya.evseev@gmail.com
#
#  Distributed as public domain from https://github.com/ilyaevseev/spamblock
#
use strict;
use warnings;

use FindBin;
use Time::Local;

my %Config = %ENV;

my $watch_iface = ($Config{IFACE} || $ARGV[0])
	or die "Configuration line missing: IFACE=<string>\n";
my $BLOCK_TTL  = $Config{BLOCK_TTL} || 3600;
my $PORT       = $Config{PORT}      || 25;

my  $blocks_filename = $Config{BLOCKS_FILE} || '/var/log/spamblock_blocklist.txt';
my   $stats_filename = $Config{STATS_FILE}  || '/var/log/spamblock_fullstats.txt';
my $import_semaphore = $Config{IMPORT_SEMAPHORE} || '/var/lock/spamblock_import.semaphore';
my $export_semaphore = $Config{EXPORT_SEMAPHORE} || '/var/lock/spamblock_export.semaphore';
my  $email_recipient = $Config{EMAIL};   # ..good for default: root@localhost?
my        %whitelist = map { $_ => 1 } split(/[,\s]\s*/, $Config{WHITELIST} || '');

my $check_policy = $Config{POLICY}
	or die "Configuration line missing: POLICY=\"count_1 period_1 count_2 period_2\"\n";
my @checks = split(/\s+/, $check_policy)
	or die "Configuration line empty: POLICY\n";
die "Policy MUST be even-sized in \"count period ...\" format"
	if @checks % 2;

my %stats;   # IP => { count => lasttime, ... }
my %blocks;  # IP => 1
my $tstamp = time;
my $tstart = $tstamp;
my $total_checks = 0;
my $total_blocks = 0;

my $fw;

#use Data::Dumper;

sub tprint {
	my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($tstamp);
	printf("[ %04d.%02d.%02d %02d:%02d:%02d ]  @_\n",
		$year+1900, $mon+1, $mday, $hour, $min, $sec);
}

sub import_state() {
	tprint "Import state...";
	my %new_blocks;
	$fw->import_state(\%new_blocks);
	my ($readed, $added, $deleted, $total) = (0,0,0,0);
	while (my ($ip, undef) = each %blocks) {
		$total++;
		next if $new_blocks{$ip};
		$deleted++;
		delete $blocks{$ip};
		$total--;
	}
	while (my ($ip, undef) = each %new_blocks) {
		$readed++;
		next if $blocks{$ip};
		$added++;
		$blocks{$ip} = 1;
		$total++;
	}
	tprint sprintf("Import done. Total %d, readed %d, added %d, deleted %d blocks.",
		$total, $readed, $added, $deleted);
}

sub mkoutfile($$) {
	my ($fname, $desc) = @_;
	return if not $fname or $fname eq '-';
	tprint "Dump $desc to $fname...";
	my $fd;
	unless (open $fd, "> $fname") {
		print STDERR "Cannot open $fname: $!\n";
		return;
	}
	$fd;
}

sub ip2hex($) {
	my @a = split(/\./, shift);
	my $b = 0;
	$b = $b * 256 + $_ foreach @a;
	sprintf("%08X", $b);
}

sub export_blocks() {
	my $fd = mkoutfile($blocks_filename, 'blocks') or return;
	print $fd "$_\n" foreach sort { ip2hex($a) cmp ip2hex($b) } keys %blocks;
	close $fd;
}

sub export_stats() {
	$tstamp = time;
	my $fd = mkoutfile($stats_filename, 'stats') or return;
	printf $fd "# Uptime: %d seconds, %d checks, %d blocks.\n",
		($tstamp - $tstart), $total_checks, $total_blocks;
	printf $fd "# %-18s%8s  %6s", 'IP', 'Checks', 'Blocks';
	my @iplist = sort { ip2hex($a) cmp ip2hex($b) } keys %stats;
	foreach my $ip (@iplist) {
		my $stat = $stats{$ip};
		my @fields = sort {   # use numeric-based sorting for numeric fields 
			($a =~ /^\d+$/ and $b =~ /^\d+$/) ? ($a <=> $b) : ($a cmp $b);
		} keys %$stat;
		printf $fd "%-20s%8d%6s\n", $ip,
			$stat->{total_count}  || 0,
			$stat->{blocks_count} || '-';
	}
	close $fd;
}

sub export_state() {
	tprint "Dump state...";
	export_blocks();
	export_stats();
	tprint "Dump done.";
}

sub handle_semaphore($$$) {
	my ($fname, $handler, $description) = @_;
	return if not $fname or $fname eq '-' or not -w $fname;
	tprint "Found $fname semaphore, perform $description...";
	$handler->();
	unlink $fname;
	tprint "Delete $fname, $description done.";
}

my $typ = lc($Config{FIREWALL_TYPE} || 'auto');
$fw   = new ipset   (\%Config) if $typ eq 'ipset'    or ($typ eq 'auto' and -x '/sbin/ipset');
$fw ||= new iptables(\%Config) if $typ eq 'iptables' or ($typ eq 'auto' and -x '/sbin/iptables');
$fw ||= new pf      (\%Config) if $typ eq 'pf'       or ($typ eq 'auto' and -w '/dev/pf');
$fw ||= new ipfw    (\%Config) if $typ eq 'ipfw'     or ($typ eq 'auto' and -x '/sbin/ipfw');

tprint "Started now.";
import_state();

#tprint "Debug export and exit!"; export_state(); exit;

$SIG{USR1} = \&import_state;
$SIG{USR2} = \&export_state;

open F, '-|', qw/tcpdump -lnnqttpi/, $watch_iface, qw/tcp and tcp[13]==2 and dst port/, $PORT
	or die "Cannot run tcpdump: $!\n";
select((select(F), $|=1)[0]);  # ..disable buffering

while(<F>) {
	#chomp;
	#tprint "line = \"$_\"";
	next unless /^(\d+)\.(\d+) IP (\d+\.\d+\.\d+\.\d+)\.\d+ \> \d+\.\d+\.\d+\.\d+\.$PORT: /;
	my ($tstamp0, $tstamp0_msecs, $ip) = ($1, $2, $3);
	$total_checks++;

	handle_semaphore($import_semaphore, \&import_state, 'import');
	handle_semaphore($export_semaphore, \&export_state, 'export');

	my $s = ($stats{$ip} ||= {});
	($s->{total_count} ||= 0)++;

	$tstamp = time;
	next if $whitelist{$ip};
	next if $blocks{$ip} and $tstamp0 - $blocks{$ip} < $BLOCK_TTL;

	my @stats;
	my $blockmsg;
	for (my $i = 0; $i < @checks; $i+=2) {
		my $maxcount = $checks[$i];
		my $period = $checks[$i+1];
		$s->{$maxcount} ||= $tstamp0;
		next if $s->{total_count} % $maxcount;
		my $delta = $tstamp0 - $s->{$maxcount};
		push @stats, "$maxcount:$delta";
		if ($delta >= $period) {
			$s->{$maxcount} = $tstamp0;
			next;
		}
		$total_blocks++;
		($s->{blocks_count} ||= 0)++;
		$blocks{$ip} = $tstamp0;
		$blockmsg = "Block $ip: trap #$s->{blocks_count}"
			." by rule $maxcount:$period ticks:seconds,"
			." actually $delta seconds";
		$fw->block($ip);
		last;
	}
	tprint sprintf("  %-20s%8d:%d  \t@stats", $ip,
		$s->{total_count}, $tstamp - $tstart);
	next unless $blockmsg;
	tprint $blockmsg;

	# Report by email
	next if not $email_recipient or $email_recipient eq '-';
	unless (open M, "| mail -s 'SpamBlock $ip' $email_recipient") {
		warn "Cannot run mail: $!\n";
		next;
	}
	print M $blockmsg, "\n";
	close M;
}

close F;

#=======================================================================

package fwbase;

sub new($$$$$) {
	my ($class, $cfg, $paramname, $hint) = @_;
	my ($package, $filename, $line) = caller;
	::tprint "Firewall type: $package";
	my $val = $cfg->{$paramname}
		or die "Missing $hint in configuration file!\n";
	bless({ $paramname => $val }, ref($class) || $class);
}

sub import_custom($$$$) {
	my ($class, $blocks, $infile, $filter) = @_;
	open S, $infile or die "Cannot get $infile: $!\n";
	while (<S>) {
		$blocks->{$1} = 1 if $_ =~ $filter;
	}
	close S;
	$blocks;
}

#=======================================================================

package ipfw;

use base 'fwbase';

sub new($$) {
	my ($class, $cfg) = @_;
	my $self = $class->SUPER::new($cfg, 'IPFW_TABLE', 'IPFW_TABLE=<number>');
	bless($self, ref($class) || $class);
}
sub import_state($$) {
	my ($self, $blocks) = @_;
	$self->import_custom($blocks, "/sbin/ipfw table $self->{IPFW_TABLE} list |",
		'^(\d+\.\d+\.\d+\.\d+)\/\d+ \d+$');
}

sub block($$) {
	my ($self, $ip) = @_;
	system("/sbin/ipfw -q table $self->{IPFW_TABLE} add $ip");
}

#=======================================================================

package pf;

use base 'fwbase';

sub new($$) {
	my ($class, $cfg) = @_;
	my $self = $class->SUPER::new($cfg, 'PF_TABLE', 'PF_TABLE=<string>');
	bless($self, ref($class) || $class);
}

sub import_state($$) {
	my ($self, $blocks) = @_;
	$self->import_custom($blocks, "/sbin/pfctl -t $self->{PF_TABLE} -T show |",
		'^\s*(\d+\.\d+\.\d+\.\d+)$');
}

sub block($$) {
	my ($self, $ip) = @_;
	system("/sbin/pfctl -t $self->{PF_TABLE} -T add $ip");
}

#=======================================================================

package ipset;

use base 'fwbase';

sub new($$) {
	my ($class, $cfg) = @_;
	my $self = $class->SUPER::new($cfg, 'IPSET_NAME', 'IPSET_NAME=<string>');
	bless($self, ref($class) || $class);
}

sub import_state($$) {
	my ($self, $blocks) = @_;
	$self->import_custom($blocks, "/sbin/ipset -L $self->{IPSET_NAME} |",
		'^(\d+\.\d+\.\d+\.\d+)$');
}

sub block($$) {
	my ($self, $ip) = @_;
	system("/sbin/ipset -qA $self->{IPSET_NAME} $ip");
}

#=======================================================================

package iptables;

use base 'fwbase';

sub new($$) {
	my ($class, $cfg) = @_;
	my $self = $class->SUPER::new($cfg, 'IPTABLES_CHAIN', 'IPTABLES_CHAIN=<string>');
	bless($self, ref($class) || $class);
}

sub import_state($$) {
	my ($self, $blocks) = @_;
	$self->import_custom($blocks, "/sbin/iptables -nL $self->{IPTABLES_CHAIN} |",
		'^(\d+\.\d+\.\d+\.\d+)$');
}

sub block($$) {
	my ($self, $ip) = @_;
	system("/sbin/iptables -nL $self->{IPTABLES_CHAIN}"
		." | grep -q -- ' $ip '"
		." || /sbin/iptables -I $self->{IPTABLES_CHAIN} -s $ip -j DROP"
	);
}

## EOF ##
