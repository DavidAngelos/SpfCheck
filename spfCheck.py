#!/usr/bin/env python3
# -*- coding: utf-8 -*

from cortexutils.analyzer import Analyzer

import spf

class SpfCheck(Analyzer):
        def __init__(self):
                Analyzer.__init__(self)
                self.name = "SPF_Check"
        def summary(self, raw):
                taxonomies = []
                level = "malicious"
                level_s = "suspicious"
                level_sa = "safe"
                namespace = "SPF_Check"
                predicate = "tag"

                # TODO 

                return {'taxonomies': taxonomies}
        def get_info(self, data):
                try:
                        ip = ''
                        sender = ''
                        helo = ''

                        inputs = data.split('|')

                        ip = inputs[0]
                        sender = inputs[1]
                        if (len(inputs) == 3):
                                helo = inputs[2]

                        result = spf.check2(i=ip, s=sender, h=helo) 
                except SyntaxError:
                        print("Syntax Error")
                return {"SpfCheck": result}

        def run(self):
                if self.data_type == 'other':
                        data = self.get_data()
                        self.report({"SpfCheck_info": self.get_info(data)})

if __name__ == '__main__':
        SpfCheck().run()
