"""Test script for L&D"""
import unittest

class TestStringMethods(unittest.TestCase):
    """Testing string methods"""

    def test_upper(self):
        """Test upper"""
        self.assertEqual('foo'.upper(), 'FOO')

    def test_isupper(self):
        """Test is upper"""
        self.assertTrue('FOO'.isupper())
        self.assertFalse('Foo'.isupper())

    def test_split(self):
        """Test split"""
        s = 'Hello world'
        self.assertEqual(s.split(), ['hello', 'world'])
        with self.assertRaises(TypeError):
            s.split(2)

def runtest():
    """This is just for testing"""
    a = 4
    b = 2
    print(a**b)

if __name__ == '__main__':
    unittest.main()
