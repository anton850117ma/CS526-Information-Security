#!/usr/bin/python
# -*- coding: utf-8 -*-
def output(activate):
	if activate:
		print "I mean no harm."
	else:
		print "You are doomed!"
blob = """                                      �o� ӝ���GsJ�
�oƺ�n��B�zu����!���^t	#��4!.��
��_q���!��h�dK {^���H�ޗ��A�`�"�)��_�����C���;��<�S�}�L	�"qF$R1F�v/�
"""
output(ord(blob[3])==186)