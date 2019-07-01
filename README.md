# crash-analyze
AFL with asan
## command
python crash-analyze.py --download|--autoinput|--analyze [-i|l|b|p|u|t]
## three mode
### download mode
python crash-analyze.py --download -u mongo_url -t target_name_in_mongo(dbname) -i local_input_dir
### autoinput mode
python crash-analyze.py --autoinput  -i local_input_dir -b binary_path -p parameter_of_binary -l path_to_store_log
### analyze mode
python crash-analyze.py --analyze  -l log_path
