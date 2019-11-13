&CLEAN += & *~ *.tmp
&CLEAN += $(&OBJECTS)
&CLEAN += $(&DEPFILES)
&CLEAN += $(&TARGETS)

# &TARGETS_clean

&/clean::
	$(RM) $(&CLEAN)
