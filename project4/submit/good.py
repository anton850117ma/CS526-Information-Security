#!/usr/bin/python
# -*- coding: utf-8 -*-
def output(activate):
	if activate:
		print "I mean no harm."
	else:
		print "You are doomed!"
blob = """                                      �o� ӝ���GsJ�
�o�:�n��B�zu����!���^t	#��4!���
��_q�E�!��h�dK {^���H�ޗ��AL`�"�)��_�����C���;��<���}�L	�"qF$R1��v/�
"""
output(ord(blob[3])==186)