/*
    Reference: https://static1.squarespace.com/static/5b588ac24eddeca055a9e40e/t/5b64233688251b91628d2f83/1533289280041/Malware+attacks+on+Linux+servers+to+run+cryptocurrency+miners.+A+real+case+analysis.pdf
*/

rule is_pe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule is_elf
{
    strings:
        $elf = { 7f 45 4c 46 }
    condition:
        $elf in (0..4)
}

rule possible_cryptominer_minerd
{
    meta:
        author = "Joachim Suico, CivilSphere"
        date = "1/23/2018"
        description = "rule for executables based on minerd software (supports various coins)"
        reference = "https://github.com/pooler/cpuminer"
    strings:
        $crypto = "crypto" ascii nocase
        $cpuminer = "cpuminer" ascii nocase
        $minerd1 = "minerd --help" ascii nocase
        $minerd2 = "minerd [OPTIONS]" ascii nocase
        //author related information
        $author1 = "Miner by yvg1900" ascii nocase
        $author2 = "yvg1900@gmail.com" ascii nocase
        $author3 = "MINERGATE" ascii
        //some supported coins
        $coin1 = "MemoryCoin" ascii
        $coin2 = "MaxCoin" ascii
        $coin3 = "DiamondCoin" ascii
        $coin4 = "DvoraKoin" ascii
        $coin5 = "MyriadCoin" ascii
        $coin6 = "ByteCoin" ascii
        $coin7 = "QuazarCoin" ascii
        $coin8 = "FantomCoin" ascii
        $coin9 = "GroestlCoin" ascii
        $coin10 = "ProtoSharesCoin" ascii
        $coin11 = "MoneroCoin" ascii
        //sites to forward mined hashes
        $site1 = "pool.minexmr.com" ascii nocase
        $site2 = "monero.crypto-pool.fr" ascii nocase
        $site3 = "pool.cryptoescrow.eu" ascii nocase
        $site4 = "xmr.hashinvest" ascii nocase
        $site5 = "monero.farm" ascii nocase
        $site6 = "cryptonotepool.org.uk" ascii nocase
        $site7 = "monerominers.net" ascii nocase
        $site8 = "extremepool.org" ascii nocase
        $site9 = "mine.moneropool.org" ascii nocase
        $site10 = "mmcpool.com" ascii nocase
        $site11 = "dwarfpool.com" ascii nocase
        $site12 = "maxcoinpool.com" ascii nocase
        $site13 = "coinedpool.com" ascii nocase
        $site14 = "mining4all.eu" ascii nocase
        $site15 = "nut2pools.com" ascii nocase
        $site16 = "rocketpool.co.uk" ascii nocase
        $site17 = "miningpoolhub.com" ascii nocase
        $site18 = "nonce-pool.com" ascii nocase
        $site19 = "p2poolcoin.com" ascii nocase
        $site20 = "cryptity.com" ascii nocase
        $site21 = "extremepool.com" ascii nocase
        $site22 = "crypto-pool.fr" ascii nocase
        $site23 = "cryptoescrow.eu" ascii nocase
        $site24 = "moneropool.com" ascii nocase
        $site25 = "coinmine.pl" ascii nocase
        $site26 = "moneropool.com.br" ascii nocase
        $site27 = "moneropool.org" ascii nocase
        $site28 = "cryptohunger.com" ascii nocase
    condition:
        (is_elf or is_pe) and
        ((#crypto > 10 and #cpuminer > 3 and all of ($minerd*)) or
        (#crypto > 3 and 1 of ($author*) and 1 of ($coin*) and 1 of ($site*)))
}

rule possible_cryptominer_xmrig
{
    meta:
        author = "Joachim Suico, CivilSphere"
        date = "1/23/2018"
        description = "rule for executables based on XMRig (monero miner)"
        reference = "https://github.com/xmrig/xmrig"
    strings:
        $c1 = "crypto" ascii nocase
        $x1 = "xmrig" ascii nocase
        $m1 = "xmrig [OPTIONS]" ascii nocase
        $m2 = "minergate.com" ascii nocase
    condition:
        (is_elf or is_pe) and #c1 > 4 and #x1 > 5 and any of ($m*)
}

