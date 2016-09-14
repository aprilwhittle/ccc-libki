package Libki::ALMA;

use Carp;
use LWP::UserAgent;
use URI::Escape;

use XML::Simple;
$XML::Simple::PREFERRED_PARSER = 'XML::Parser';

use Data::Dumper;
$Data::Dumper::Indent = 1;

use constant DEBUG => '0';

sub authenticate_via_alma {
    my ( $c, $user, $username, $password ) = @_;

    my $log = $c->log();

    my $apikey = $c->config->{ALMA}->{apikey};
    my $host = $c->config->{ALMA}->{host};
    my $require_alma_auth = $c->config->{ALMA}->{require_alma_auth}
      // 1;

    my $userdn = {};

    my $ua = LWP::UserAgent->new ( ssl_opts => { verify_hostname => 0 } );


    my $url = sprintf "https://%s/almaws/v1/users/%s?%sapikey=%s",
                $host,
                $username,
                "view=full&expand=fees&",
                $apikey;

    my $response = $ua->get( $url );

    my $xml = $response->decoded_content;
    my $userdn = XMLin( $xml,
       ForceArray => [ 'email', 'address', 'phone', 'user_identifier', 'user_statistic' ]
       );

    my $data;
    my $patron_status_request;

    if ( $require_alma_auth ) {

        if ( $password eq '' || $username eq '') {
           return { success => 0, error => 'INVALID_USER', user => $user };
        }

        if ( $userdn->{primary_id} eq $password ) {
           }
           else {
                return { success => 0, error => 'INVALID_USER', user => $user };
                }
    }

    if ($user) {    ## User authenticated and exists in Libki
        $user->set_column( 'password', $password );
        $user->update();
        }
        else {          ## User authenticated and does not exist in Libki
        my $minutes =
          $c->model('DB::Setting')->find('DefaultTimeAllowance')->value;

        $user = $c->model('DB::User')->create(
            {
                username          => $username,
                password          => $password,
                minutes_allotment => $minutes,
                status            => 'enabled',
            }
        );
    }

    if ( my $deny_on = $c->config->{ALMA}->{deny_on} ) {
        my @deny_on = ref($deny_on) eq "ARRAY" ? @$deny_on : $deny_on;

        foreach my $d (@deny_on) {
            if ( $userdn->{user_blocks}->{user_block}->[0]->{block_status} eq 'INACTIVE' ) {
                return {
                    success => 0,
                    error   => 'ACCOUNT_INACTIVE',
                    user    => $user
                };
            }
        }

        if ( my $fee_limit = $c->config->{ALMA}->{fee_limit} ) {

            if ( $userdn->{fees}->{content} > $fee_limit ) {
                return {
                    success => 0,
                    error   => 'FEE_LIMIT',
                    details => {$fee_limit => $fee_limit },
                    user    => $user
                };
            }
        }
    }

    return { success => 1, user => $user };

}

1;
