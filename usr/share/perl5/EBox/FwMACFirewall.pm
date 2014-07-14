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
use EBox::Sudo;

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

	EBox::Sudo::root('/sbin/iptables -N allowmacs >/dev/null 2>&1 || true');

	foreach my $ifc (@ifaces) {
		# add at first position of INPUT chain
		EBox::Sudo::root("/sbin/iptables -nvL INPUT| egrep -q '.*(allowmacs).*($ifc).*' || /sbin/iptables -I INPUT -i $ifc -j allowmacs");
	}

	foreach my $object (@{$obj->objects}) {
		my $obj_desc = $obj->objectDescription($object->{id});

		# Only OBJECT name => allowed
		#next unless ($obj_desc eq 'allowmacs');

		my $members = $obj->objectMembers($object->{id});
		foreach my $member (@{$members}) {
			my $mac = $member->{macaddr};

			defined($mac) or next;
			($mac ne "") or next;

			my $address = $member->{ipaddr};
			my $name = $member->{name};
			#print "IP=$address MAC=$mac NAME=$name\n";
			foreach my $ifc (@ifaces) {
				# FIXME ACCEPT or RETURN
				my $r="-i $ifc -m mac --mac-source $mac -m comment --comment 'IP=$address NAME=$name OBJ=$obj_desc' -j ACCEPT";
				#push(@rules, $r);
				push(@rules, { 'rule' => $r, 'chain' => 'allowmacs' });
				}
		}

	}

	# reject if any rule
	my $size=scalar @rules;
	if ( $size > 0 ) {
		# reject other traffic
		foreach my $ifc (@ifaces) {
			#my $r="-i $ifc -j LOG --log-prefix '[NO ALLOW MAC $ifc] '";
			#push(@rules, { 'rule' => $r, 'chain' => 'allowmacs' });
			#my $r="-i $ifc -j DROP";
			my $r="-i $ifc -j idrop";
			push(@rules, { 'rule' => $r, 'chain' => 'allowmacs' });
		}
	}

	return \@rules;
}



1;
