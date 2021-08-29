package main

import (
	"fmt"
	"github.com/Knetic/govaluate"
	"testing"
)

func TestName(t *testing.T) {
	e := `(([c-useragent] =~ ['Mozilla.*5.0.*Windows.*NT.*6.1.*WOW64.*rv.*53.0.*Gecko.*20100101.*Chrome.*53.0']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*8.0.*Windows.*NT.*5.1.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*7.0.*Windows.*NT.*5.1.*Trident.*4.0.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*6.0.*Windows.*NT.*5.0.*.NET.*CLR.*1.1.4322.*']) || ([c-useragent] =~ ['HttpBrowser.*1.0']) || ([c-useragent] =~ ['.*.*.*']) || ([c-useragent] =~ ['nsis.*inetc.*mozilla.*']) || ([c-useragent] =~ ['Wget.*1.9.*cvs.*stable.*Red.*Hat.*modified.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*8.0.*Windows.*NT.*6.1.*Trident.*4.0.*.NET.*CLR.*1.1.4322.*']) || ([c-useragent] =~ ['.*zeroup.*']) || ([c-useragent] =~ ['Mozilla.*5.0.*Windows.*NT.*5.1.*.*v..*']) || ([c-useragent] =~ ['.*adlib.*']) || ([c-useragent] =~ ['.*tiny']) || ([c-useragent] =~ ['.*BGroom.*']) || ([c-useragent] =~ ['.*changhuatong']) || ([c-useragent] =~ ['.*CholTBAgent']) || ([c-useragent] =~ ['Mozilla.*5.0.*WinInet']) || ([c-useragent] =~ ['RookIE.*1.0']) || ([c-useragent] =~ ['M']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*8.0.*Windows.*NT.*5.1.*Trident.*4.0.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*7.0.*Windows.*NT.*6.0.*']) || ([c-useragent] =~ ['backdoorbot']) || ([c-useragent] =~ ['Mozilla.*5.0.*Windows.*U.*Windows.*NT.*5.1.*en.*US.*rv.*1.9.2.3.*Gecko.*20100401.*Firefox.*3.6.1.*.NET.*CLR.*3.5.30731.*']) || ([c-useragent] =~ ['Opera.*8.81.*Windows.*NT.*6.0.*U.*en.*']) || ([c-useragent] =~ ['Mozilla.*5.0.*Windows.*U.*Windows.*NT.*5.1.*en.*US.*rv.*1.9.2.3.*Gecko.*20100401.*Firefox.*3.6.1.*.NET.*CLR.*3.5.30729.*']) || ([c-useragent] =~ ['Opera']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*5.0.*Windows.*98.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*5.01.*Windows.*NT.*5.0.*']) || ([c-useragent] =~ ['MSIE']) || ([c-useragent] =~ ['.*Charon.*Inferno.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*8.0.*Windows.*NT.*5.1.*Trident.*5.0.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*6.1.*Windows.*NT.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*6.0.*Windows.*NT.*5.1.*']) || ([c-useragent] =~ ['Mozilla.*5.0.*Windows.*NT.*10.0.*Win64.*x64.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*8.0.*Windows.*NT.*10.0.*Win64.*x64.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*8.0.*Windows.*NT.*6.1.*Win64.*x64.*']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*7.0.*Windows.*NT.*6.2.*WOW64.*Trident.*7.0.*.NET4.0C.*.NET4.0E.*InfoPath.3.*']) || ([c-useragent] =~ ['.*pxyscand.*']) || ([c-useragent] =~ ['.*asd']) || ([c-useragent] =~ ['.*mdms']) || ([c-useragent] =~ ['sample']) || ([c-useragent] =~ ['nocase']) || ([c-useragent] =~ ['Moxilla']) || ([c-useragent] =~ ['Win32.*']) || ([c-useragent] =~ ['.*Microsoft.*Internet.*Explorer.*']) || ([c-useragent] =~ ['agent.*']) || ([c-useragent] =~ ['AutoIt']) || ([c-useragent] =~ ['IczelionDownLoad']) || ([c-useragent] =~ ['Mozilla.*4.0.*compatible.*MSIE.*9.0.*Windows.*NT.*10.0.*.NET4.0C.*.NET4.0E.*Tablet.*PC.*2.0.*']))`
	exp, err := govaluate.NewEvaluableExpression(e)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(exp)
	m := map[string]interface{}{
		"c-useragent" : "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Chrome /53.0",
	}
	fmt.Println(exp.Evaluate(m))
}