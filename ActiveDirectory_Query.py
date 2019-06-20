#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer


class ActiveDirectoryAnalyzer(Analyzer):

    #Handle configuration file options
    def __init__(self):
        Analyzer.__init__(self)
    
    #Generate Short report
    def summary(self, raw):
        return {"taxonomies": taxonomies}
    
    #Analyzer main function
    def run(self):
        return ""

if __name__ == '__main__':
    ActiveDirectoryAnalyzer().run()
