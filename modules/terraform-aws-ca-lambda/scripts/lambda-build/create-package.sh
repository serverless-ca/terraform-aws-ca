#!/bin/sh

echo "Executing create_package.sh..."

# Check Python version matches runtime
python_minor_version="$(python3 --version)"
python_version="${python_minor_version%.*}"
prefix="Python "
local_version="${python_version#$prefix}"
runtime_prefix="python"
lambda_version="${runtime#$runtime_prefix}"

if [ "$lambda_version" != "$local_version" ]; then
  echo "Error: local Python version does not match Lambda Python runtime"
  echo "Local Python version: $local_version"
  echo "Lambda Python version: $lambda_version"
  exit 1
fi

dir_name=$function_name/
mkdir -p $path_cwd/build/$dir_name

# Create and activate virtual environment...
python3 -m venv $path_cwd/build/env_$function_name
source $path_cwd/build/env_$function_name/bin/activate

# Installing python dependencies...
FILE=$path_cwd/lambda_code/$function_name/requirements.txt


if [ -f "$FILE" ]; then
  echo "Installing dependencies..."
  echo "From: requirements.txt file exists..."
  pip install --platform $platform --target $path_cwd/build/env_$function_name/lib/$runtime/site-packages --only-binary=:all: --implementation cp -r "$FILE"
  # pip install --platform $platform --target $path_cwd/build/env_$function_name/lib/$runtime/site-packages --only-binary=:all: --implementation cp --python $runtime -r "$FILE"
  # pip install -r "$FILE"

else
  echo "Error: requirements.txt does not exist!"
fi

# Deactivate virtual environment...
deactivate

# Create deployment package...
echo "Creating deployment package..."
cp -r $path_cwd/build/env_$function_name/lib/$runtime/site-packages/. $path_cwd/build/$dir_name
cp -r $path_cwd/lambda_code/$function_name/. $path_cwd/build/$dir_name
cp -r $path_cwd/utils $path_cwd/build/$dir_name

# Removing virtual environment folder...
echo "Removing virtual environment folder..."
rm -rf $path_cwd/build/env_$function_name

echo "Finished script execution!"
