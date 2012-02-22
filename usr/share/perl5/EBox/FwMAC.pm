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
                                    'order' => 229));
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
    my $titles = [__('IP address'),__('MAC address'), __('Host name')];

    my $ids = []; 
    my $rows = {};

    open(my $FD, '/var/lib/misc/dnsmasq.leases');
    while(my $line = <$FD>) {
        chomp($line);
        my ($datetime, $mac, $ip, $name) = split(' ',$line);
            push(@{$ids}, $ip);
            $rows->{$ip} = [$ip, $mac, $name];
    }
    close($FD);

    $section->add(new EBox::Dashboard::List(undef, $titles, $ids, $rows));
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
