#!/bin/sh

javac -encoding US-ASCII -g:none -source 1.3 -target 1.2 basE91.java b91cli.java && \
jar cvfm base91.jar manifest.mf b91cli.class basE91.class license.txt readme.txt
