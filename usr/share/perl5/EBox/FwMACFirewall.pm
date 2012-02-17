# Copyright (C) 2011 Mario Izquierdo (mariodebian) for Comunidad de Madrid
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

package EBox::FwMACFirewall;
use strict;
use warnings;

use base 'EBox::FirewallHelper';

use EBox::Objects;
use EBox::Global;
use EBox::Config;
use EBox::Firewall;
use EBox::Gettext;

sub new
{
        my $class = shift;
        my %opts = @_;
        my $self = $class->SUPER::new(@_);
        bless($self, $class);
        return $self;
}

sub input
{
	my $self = shift;
	my @rules = ();

	my $net = EBox::Global->modInstance('network');
	my @ifaces = @{$net->InternalIfaces()};


	my $obj = EBox::Global->modInstance('objects');


	for my $id (@{$obj->{objectModel}->ids()}) {
		my $members = $obj->objectMembers($id);
		foreach my $member (@{$members}) {
			my $mac = $member->{macaddr};
			if (defined($mac)) {
			    my $address = $member->{ipaddr};
			    my $name = $member->{ipaddr};
			    print "IP=$address MAC=$mac NAME=$name\n";
			    foreach my $ifc (@ifaces) {
				my $r="-i $ifc -m mac --mac-source $mac -m comment --comment 'IP=$address NAME=$name' -j ACCEPT";
				push(@rules, $r);
			    }
			}
		}
	}

	# reject other traffic
	foreach my $ifc (@ifaces) {
		my $r="-i $ifc -j REJECT";
		push(@rules, $r);
	}

	return \@rules;
}


#sub output2
#{
#	my $self = shift;
#	my @rules = ();
#
#	my $net = EBox::Global->modInstance('network');
#	my @ifaces = @{$net->InternalIfaces()};
#
#        foreach my $port (UDPPORTS) {
#            foreach my $ifc (@ifaces) {
#                my $r = "-m state --state NEW -o $ifc  ".
#                     "-p udp --dport $port -j ACCEPT";
#                push(@rules, $r);
#            }
#        }
#
#    return \@rules;
#}


1;
