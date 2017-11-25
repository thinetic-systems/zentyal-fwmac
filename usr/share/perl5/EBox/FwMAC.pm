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

package EBox::FwMAC;

use strict;
use warnings;

use base qw(EBox::Module::Service
            EBox::FirewallObserver
            );

use EBox::Exceptions::DataExists;
use EBox::Gettext;
use EBox::Menu::Item;
use EBox::Service;
use EBox::Sudo qw ( :all );
use EBox::Validate qw ( :all );
use File::Temp qw( tempfile tempdir );
use EBox::FwMACFirewall;

use EBox::Dashboard::Section;
use EBox::Dashboard::List;

sub _create
{
    my $class = shift;
    my $self = $class->SUPER::_create(name => 'fwmac',
                      printableName => 'Cortafuegos por MAC',
                      @_);
    bless($self, $class);
    return $self;
}

# Method: menu
#
#       Overrides EBox::Module method.
sub menu
{
    my ($self, $root) = @_;
    $root->add(new EBox::Menu::Item('url' => 'FwMAC/Index',
                                    'text' => $self->printableName(),
                                    'separator' => 'Gateway',
                                    'icon' => 'firewall',
                                    'order' => 229));
}

sub _generateDNSmasq
{
    my $log = EBox::logger;
    $log->info("FWMAC => _generateDNSmasq()");

    my $dhcpFile = new File::Temp(TEMPLATE => 'dnsmasq.mac.conf-XXXXXX',
                                 DIR      => EBox::Config::tmp());

    open DHCPFILE, ">$dhcpFile";
    my $obj = EBox::Global->modInstance('network');

    foreach my $object (@{$obj->objects}) {
        my $obj_desc = $obj->objectDescription($object->{id});
        
        my $members = $obj->objectMembers($object->{id});
        foreach my $member (@{$members}) {
            my $mac = $member->{macaddr};
            
            defined($mac) or next;
            ($mac ne "") or next;

            my $address = $member->{ipaddr};
            $address =~ s/\/32//;
            my $name = $member->{name};
            
            $log->info("FWMAC => firewallHelper dhcp-host=$mac,$address,$name");
            if ( index($address, '127.1') == -1 ) {
                print DHCPFILE "dhcp-host=$mac,$address,$name\n";
            }
        }
    }

    close (DHCPFILE);
    # /etc/init.d/dnsmasq stop
    # :> /var/lib/misc/dnsmasq.leases
    # sleep 1
    # /etc/init.d/dnsmasq start

    EBox::Sudo::root("cp $dhcpFile /etc/dnsmasq.mac.conf",
                     "service dnsmasq stop",
                     "cat /dev/null > /var/lib/misc/dnsmasq.leases",
                     "sleep 1",
                     "service dnsmasq start");
}

sub _preServiceHook
{
    my ($self, $enabled) = @_;
    
    my $log = EBox::logger;
    $log->info("FWMAC => _preServiceHook");
    
    if(! $enabled) {
        EBox::Sudo::root('for n in $(iptables -nvL INPUT --line-numbers | grep allowmacs | tac | awk \'{print $1}\'); do iptables -D INPUT $n ; done',
                         "iptables -F allowmacs >/dev/null 2>&1||true",
                         "iptables -X allowmacs >/dev/null 2>&1||true");
        
    }



    return $self->SUPER::_preServiceHook($enabled);
}

sub _postServiceHook
{
    my ($self, $enabled) = @_;
    $self->_generateDNSmasq();
    return $self->SUPER::_postServiceHook($enabled);
}

sub firewallHelper
{
    my ($self) = @_;
    
    if ($self->isEnabled()){
        return new EBox::FwMACFirewall();
    }
    return undef;
}


sub dnsmasqLeasesWidget
{
    my ($self, $widget) = @_;

    my $section = new EBox::Dashboard::Section('dnsmasqleases');
    $widget->add($section);
    #my $titles = [__('IP address'),__('MAC address'), __('Host name'), __('Date')];
    my $titles = [__('IP address'),__('MAC address'), __('Host name')];

    my $rows = {};

    open(my $FD, '/var/lib/misc/dnsmasq.leases');
    while(my $line = <$FD>) {
        chomp($line);
        my ($datetime, $mac, $ip, $name) = split(' ',$line);
        my ($ipa, $ipb, $ipc, $ipd) = split('\.', $ip);

        #my ($S,$M,$H,$d,$m,$Y) = localtime($datetime,);
        #$m += 1;
        #$Y += 1900;
        #my $dt = sprintf("%04d-%02d-%02d %02d:%02d:%02d", $Y,$m,$d, $H,$M,$S);

        #$rows->{$ipd} = [$ip, $mac, $name, $dt];
        $rows->{"dnsmasq-$ipa-$ipb-$ipc-$ipd"} = [$ip, $mac, $name];
    }
    close($FD);

    # sort ids array
    my $sorted=[];
    #foreach my $id (sort {$a<=>$b} keys (%{$rows})) {
    foreach my $id (sort {lc $a cmp lc $b} keys (%{$rows})) {
      #print "id=$id\n";
      push(@{$sorted}, $id);
    }

    $section->add(new EBox::Dashboard::List(undef, $titles, $sorted, $rows));
}

sub widgets
{
    return {
        'dnsmasqleases' => {
            'title' => "DHCP dnsmasq",
            'widget' => \&dnsmasqLeasesWidget,
            'order' => 5,
            'default' => 1
        }
    };
}




1;
