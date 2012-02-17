package EBox::CGI::FwMAC::Index;

use strict;
use warnings;

use base 'EBox::CGI::ClientBase';

use EBox::Global;
use EBox::Gettext;

## arguments:
## 	title [required]
sub new {
	my $class = shift;
	my $self = $class->SUPER::new('title'    => __('FW por MAC'),
				      'template' => 'fwmac/index.mas',
				      @_);
	bless($self, $class);
	return $self;
}

sub _process($) {
	my $self = shift;
	$self->{title} = __('FW MAC');
	my $fwmac = EBox::Global->modInstance('fwmac');

	my @array = ();
	my $active = 'no';
	if ($fwmac->isEnabled()) {
	    $active = 'yes';
	}

	push (@array, 'active' => $active);

	$self->{params} = \@array;
}


1;
