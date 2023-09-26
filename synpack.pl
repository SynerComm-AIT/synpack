use strict;
use warnings;
use File::stat;
use File::Copy;
use Term::ANSIColor qw(:constants);
use Bytes::Random::Secure qw(random_bytes);
use Crypt::Mode::CBC;


sub print_header {
    my $logo = <<'LOGO';
 ____                               _    
/ ___| _   _ _ __  _ __   __ _  ___| | __
\___ \| | | | '_ \| '_ \ / _` |/ __| |/ /
 ___) | |_| | | | | |_) | (_| | (__|   < 
|____/ \__, |_| |_| .__/ \__,_|\___|_|\_\
       |___/      |_|                    
LOGO
    print(BOLD, BRIGHT_BLUE, "$logo v0.1\n", RESET);
}

sub c_print {
    my ($stmt, $val) = @_;

    print(BOLD, BRIGHT_CYAN, "$stmt", RESET);
    print("$val\n") if defined $val;
}

sub aes_encrypt {
    my $data = shift;

    my $key = random_bytes(16);
    my $iv  = random_bytes(16);

    my $cbc = Crypt::Mode::CBC->new('AES');

    my $ciphertext = $cbc->encrypt($data, $key, $iv);

    return $ciphertext, $key, $iv;
}

# for debug
sub hex_print_file {
    my $file = shift;

    my $buffer;

    my $stat = stat($file);
    my $filesize = $stat->size;
    print("$filesize\n");

    my $bytes_read = 0;
    while (read($file, $buffer, 1) != 0) {
        my $comma = ",";
        $comma = "\n" if ($bytes_read == $filesize - 1);
        printf("0x%02x$comma", ord($buffer));
        $bytes_read++;
    }
}

sub get_file_bytes {
    my $file = shift;

    my $buffer;

    my $stat = stat($file);
    my $filesize = $stat->size;
    print("$filesize\n");

    read($file, $buffer, $filesize);

    return $buffer;
}

sub hex_format_data {
    my $data = shift;

    my $hex_str = join(',', map { sprintf("0x%02x", $_) } unpack('C*', $data));

    return $hex_str;
}



print_header();
my $filepath = shift @ARGV || die("Please pass file path to .NET executable!\n");

c_print("[+] Opening: ", $filepath);

open(my $file, "<:raw", $filepath) or die("[!] Cant open file! $!\n");

#hex_print_file($file);
my $file_bytes = get_file_bytes($file);
close($file);
hex_format_data($file_bytes);

c_print("[+] Encrypting .NET executable\n");

my ($enc_data, $key, $iv) = aes_encrypt($file_bytes);

my $hex_data = hex_format_data($enc_data);
my $hex_key  = hex_format_data($key);
my $hex_iv   = hex_format_data($iv);

print("AES Data: $hex_data\n");
print("AES Key: $hex_key\n");
print("AES IV: $hex_iv\n");

c_print("==> Copying template.rs to src/main.rs");

copy("template.rs", "src\\main.rs") or die("Copy failed: $!\n");
