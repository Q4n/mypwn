rm -rf dist/*
python setup.py sdist
twine upload dist/*
find . -name "__pycache__"  | xargs rm -rf
find . -name "*.pyc"  | xargs rm -f
rm -rf q4n.egg-info
