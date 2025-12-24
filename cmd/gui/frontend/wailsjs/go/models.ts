export namespace vault {
	
	export class FileEntry {
	    Name: string;
	    Size: number;
	    IsDir: boolean;
	    MTime: number;
	    Mode: number;
	
	    static createFrom(source: any = {}) {
	        return new FileEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Name = source["Name"];
	        this.Size = source["Size"];
	        this.IsDir = source["IsDir"];
	        this.MTime = source["MTime"];
	        this.Mode = source["Mode"];
	    }
	}

}

