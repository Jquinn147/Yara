rule gh0strat_variant_dropper
{
	meta:
	    author = "James Quinn, @lazyactivist192"
	    desc = "Identifies a Gh0stRAT dropper"

	strings:
	    $s1 = "+gPp6bGvrqa9/fz2770A/amupqawrp8="
	    $s2 = "Shellex"
	    $s3 = "SUSRAIZCqllahrCohrlojSarZSalpecasZ"
	    $s4 = "[printto(\"%1\",\"%2\",\"%3\",\"%4\")]"

	    $s6 = "SYST%-\\#urrENt#ONtrOLSEt\\SErvICEs\\"
	
	condition:
	    2 of ($s1, $s2, $s4) and 1 of ($s3, $s6)
}
rule gh0strat_variant
{
 	meta:
	    author = "James Quinn, @lazyactivist192"
	    desc = "Identifies a Gh0stRAT variant"
	
	strings:
	    $s1 = "\\\\.\\agmkis2"
	    $s2 = "Shellex"
	    $s3 = "Gh0st Update"
	    $s4 = "PluginMe"
	
	condition:
	    all of them
} 
