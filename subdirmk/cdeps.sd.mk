
&DEPFILES += $(foreach b,$(patsubst %.o,%,$(&OBJECTS)), \
		$(dir $b).$(notdir $b).d)
-include $(&DEPFILES)

