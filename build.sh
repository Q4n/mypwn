rm -rf dist/*
python setup.py sdist
twine upload dist/*
find . -name "*.pyc"  | xargs rm -f
rm -rf q4n.egg-info